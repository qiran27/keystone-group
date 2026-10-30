#include "group_task.h"

#include <string.h>

static int lane_index_from_id(uint64_t lane_id)
{
  if (!lane_id || lane_id > KEYSTONE_GROUP_TASK_MAX_LANES)
    return -1;
  return (int)(lane_id - 1);
}

static struct keystone_group_stage_slot* find_stage(
    struct keystone_group_task_scheduler* scheduler,
    uint64_t job_id, uint64_t stage_id)
{
  size_t i;

  for (i = 0; i < KEYSTONE_GROUP_TASK_MAX_STAGES; i++)
    if (scheduler->stages[i].state != KEYSTONE_GROUP_STAGE_PENDING &&
        scheduler->stages[i].descriptor.job_id == job_id &&
        scheduler->stages[i].descriptor.stage_id == stage_id)
      return &scheduler->stages[i];
  return 0;
}

static int stage_dependencies_satisfied(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_stage_slot* stage)
{
  uint64_t dependencies = stage->descriptor.dependency_mask;
  uint64_t bit;

  for (bit = 0; bit < 64; bit++) {
    struct keystone_group_stage_slot* dependency;

    if (!(dependencies & (UINT64_C(1) << bit)))
      continue;
    dependency = find_stage(scheduler, stage->descriptor.job_id, bit);
    if (!dependency || dependency->state != KEYSTONE_GROUP_STAGE_SUCCEEDED)
      return 0;
  }
  return 1;
}

static struct keystone_group_task_job_fairness* find_or_add_job(
    struct keystone_group_task_scheduler* scheduler,
    uint64_t job_id, uint64_t weight)
{
  size_t i;
  struct keystone_group_task_job_fairness* free_job = 0;

  for (i = 0; i < KEYSTONE_GROUP_TASK_MAX_JOBS; i++) {
    struct keystone_group_task_job_fairness* job = &scheduler->jobs[i];
    if (job->valid && job->job_id == job_id)
      return job;
    if (!job->valid && !free_job)
      free_job = job;
  }
  if (!free_job)
    return 0;
  free_job->valid = 1;
  free_job->job_id = job_id;
  free_job->weight = weight ? weight : 1;
  if (free_job->weight > KEYSTONE_GROUP_TASK_MAX_WEIGHT)
    free_job->weight = KEYSTONE_GROUP_TASK_MAX_WEIGHT;
  return free_job;
}

static uint64_t task_hard_lane_mask(
    const struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_task_descriptor* task)
{
  uint64_t allowed = scheduler->active_worker_mask;

  if (task->active_worker_mask)
    allowed &= task->active_worker_mask;
  return allowed;
}

static int task_is_dispatchable(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_task_slot* task)
{
  struct keystone_group_stage_slot* stage;

  if (task->state != KEYSTONE_GROUP_TASK_STATE_QUEUED &&
      task->state != KEYSTONE_GROUP_TASK_STATE_RETRY)
    return 0;
  stage = find_stage(scheduler, task->descriptor.job_id,
                     task->descriptor.stage_id);
  return stage && stage_dependencies_satisfied(scheduler, stage) &&
         stage->state != KEYSTONE_GROUP_STAGE_FAILED &&
         stage->state != KEYSTONE_GROUP_STAGE_CANCELLED;
}

static int choose_lane(struct keystone_group_task_scheduler* scheduler,
                       const struct keystone_group_task_descriptor* task,
                       uint64_t reserved_mask)
{
  uint64_t hard_allowed = task_hard_lane_mask(scheduler, task);
  uint64_t allowed = task->preferred_lane_mask ?
      task->preferred_lane_mask & hard_allowed : hard_allowed;
  int fallback = -1;
  size_t i;

  for (i = 0; i < KEYSTONE_GROUP_TASK_MAX_LANES; i++) {
    struct keystone_group_task_lane* lane = &scheduler->lanes[i];
    uint64_t bit = UINT64_C(1) << lane->lane_id;

    if (!(allowed & bit) || (reserved_mask & bit) || lane->busy)
      continue;
    if (lane->resident_bank == task->input_bank)
      return (int)i;
    if (fallback < 0)
      fallback = (int)i;
  }
  if (fallback >= 0)
    return fallback;

  allowed = hard_allowed;
  for (i = 0; i < KEYSTONE_GROUP_TASK_MAX_LANES; i++) {
    struct keystone_group_task_lane* lane = &scheduler->lanes[i];
    uint64_t bit = UINT64_C(1) << lane->lane_id;

    if ((allowed & bit) && !(reserved_mask & bit) && !lane->busy)
      return (int)i;
  }
  return -1;
}

static int fair_job_precedes(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_task_slot* candidate,
    const struct keystone_group_task_slot* selected)
{
  struct keystone_group_task_job_fairness* left;
  struct keystone_group_task_job_fairness* right;

  if (!selected)
    return 1;
  if (scheduler->mode == KEYSTONE_GROUP_TASK_SCHED_ROUND_ROBIN) {
    struct keystone_group_task_job_fairness* left_job =
        find_or_add_job(scheduler, candidate->descriptor.job_id,
                        candidate->descriptor.weight);
    struct keystone_group_task_job_fairness* right_job =
        find_or_add_job(scheduler, selected->descriptor.job_id,
                        selected->descriptor.weight);
    uint64_t left_index;
    uint64_t right_index;
    uint64_t left_distance;
    uint64_t right_distance;

    if (!left_job || !right_job)
      return candidate->submit_sequence < selected->submit_sequence;
    if (left_job == right_job)
      return candidate->submit_sequence < selected->submit_sequence;
    left_index = (uint64_t)(left_job - scheduler->jobs);
    right_index = (uint64_t)(right_job - scheduler->jobs);
    left_distance = (left_index + KEYSTONE_GROUP_TASK_MAX_JOBS -
                     scheduler->rr_job_cursor) %
                    KEYSTONE_GROUP_TASK_MAX_JOBS;
    right_distance = (right_index + KEYSTONE_GROUP_TASK_MAX_JOBS -
                      scheduler->rr_job_cursor) %
                     KEYSTONE_GROUP_TASK_MAX_JOBS;
    return left_distance < right_distance;
  }
  if (scheduler->mode != KEYSTONE_GROUP_TASK_SCHED_FAIR)
    return candidate->submit_sequence < selected->submit_sequence;
  left = find_or_add_job(scheduler, candidate->descriptor.job_id,
                         candidate->descriptor.weight);
  right = find_or_add_job(scheduler, selected->descriptor.job_id,
                          selected->descriptor.weight);
  if (!left || !right)
    return candidate->submit_sequence < selected->submit_sequence;
  {
    uint64_t left_quotient = left->service_units / left->weight;
    uint64_t right_quotient = right->service_units / right->weight;
    uint64_t left_fraction;
    uint64_t right_fraction;

    if (left_quotient != right_quotient)
      return left_quotient < right_quotient;
    left_fraction = (left->service_units % left->weight) * right->weight;
    right_fraction = (right->service_units % right->weight) * left->weight;
    if (left_fraction != right_fraction)
      return left_fraction < right_fraction;
  }
  return candidate->submit_sequence < selected->submit_sequence;
}

static int dispatch_one(struct keystone_group_task_scheduler* scheduler,
                        size_t task_index, int lane_index,
                        struct keystone_group_task_descriptor* out_task,
                        uint64_t* out_lane)
{
  struct keystone_group_task_slot* task = &scheduler->tasks[task_index];
  struct keystone_group_task_lane* lane = &scheduler->lanes[lane_index];
  struct keystone_group_stage_slot* stage;
  struct keystone_group_task_job_fairness* job;

  task->state = KEYSTONE_GROUP_TASK_STATE_RUNNING;
  task->assigned_lane = lane->lane_id;
  lane->busy = 1;
  lane->task_index = task_index;
  scheduler->queued_count--;
  scheduler->running_count++;
  scheduler->dispatch_sequence++;
  stage = find_stage(scheduler, task->descriptor.job_id,
                     task->descriptor.stage_id);
  if (stage)
    stage->state = KEYSTONE_GROUP_STAGE_RUNNING;
  job = find_or_add_job(scheduler, task->descriptor.job_id,
                        task->descriptor.weight);
  if (job) {
    uint64_t units = task->descriptor.length ? task->descriptor.length : 1;
    job->service_units = UINT64_MAX - job->service_units < units ?
        UINT64_MAX : job->service_units + units;
    if (scheduler->mode == KEYSTONE_GROUP_TASK_SCHED_ROUND_ROBIN)
      scheduler->rr_job_cursor =
          ((uint64_t)(job - scheduler->jobs) + 1) %
          KEYSTONE_GROUP_TASK_MAX_JOBS;
  }
  *out_task = task->descriptor;
  *out_lane = lane->lane_id;
  return KEYSTONE_GROUP_TASK_OK;
}

static void update_stage_completion(
    struct keystone_group_task_scheduler* scheduler,
    uint64_t job_id, uint64_t stage_id)
{
  struct keystone_group_stage_slot* stage =
      find_stage(scheduler, job_id, stage_id);
  size_t i;
  int has_task = 0;

  if (!stage)
    return;
  for (i = 0; i < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY; i++) {
    const struct keystone_group_task_slot* task = &scheduler->tasks[i];
    if (task->state == KEYSTONE_GROUP_TASK_STATE_FREE ||
        task->descriptor.job_id != job_id ||
        task->descriptor.stage_id != stage_id)
      continue;
    has_task = 1;
    if (task->state == KEYSTONE_GROUP_TASK_STATE_FAILED) {
      stage->state = KEYSTONE_GROUP_STAGE_FAILED;
      return;
    }
    if (task->state != KEYSTONE_GROUP_TASK_STATE_SUCCEEDED &&
        task->state != KEYSTONE_GROUP_TASK_STATE_CANCELLED)
      return;
  }
  if (has_task)
    stage->state = KEYSTONE_GROUP_STAGE_SUCCEEDED;
}

void keystone_group_task_scheduler_init(
    struct keystone_group_task_scheduler* scheduler,
    uint64_t mode, uint64_t active_worker_mask)
{
  size_t i;

  if (!scheduler)
    return;
  memset(scheduler, 0, sizeof(*scheduler));
  scheduler->mode =
      (mode == KEYSTONE_GROUP_TASK_SCHED_FAIR ||
       mode == KEYSTONE_GROUP_TASK_SCHED_ROUND_ROBIN) ?
      mode : KEYSTONE_GROUP_TASK_SCHED_FIFO;
  scheduler->active_worker_mask = active_worker_mask & UINT64_C(0xe);
  for (i = 0; i < KEYSTONE_GROUP_TASK_MAX_LANES; i++) {
    scheduler->lanes[i].lane_id = i + 1;
    scheduler->lanes[i].task_index = KEYSTONE_GROUP_TASK_QUEUE_CAPACITY;
    scheduler->lanes[i].prefetched_task_index =
        KEYSTONE_GROUP_TASK_QUEUE_CAPACITY;
    scheduler->lanes[i].resident_bank = KEYSTONE_YXSTM_INVALID_BANK;
  }
  for (i = 0; i < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY; i++)
    scheduler->tasks[i].assigned_lane = KEYSTONE_GROUP_TASK_NO_LANE;
}

int keystone_group_task_add_stage(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_stage_descriptor* stage)
{
  size_t i;
  uint64_t dependency;

  if (!scheduler || !stage || stage->stage_id >= 64 ||
      !stage->required_workers ||
      stage->required_workers > KEYSTONE_GROUP_TASK_MAX_LANES ||
      (stage->dependency_mask & (UINT64_C(1) << stage->stage_id)) ||
      find_stage(scheduler, stage->job_id, stage->stage_id))
    return KEYSTONE_GROUP_TASK_ERR_ARGUMENT;
  for (dependency = 0; dependency < 64; dependency++)
    if ((stage->dependency_mask & (UINT64_C(1) << dependency)) &&
        !find_stage(scheduler, stage->job_id, dependency))
      return KEYSTONE_GROUP_TASK_ERR_ARGUMENT;
  for (i = 0; i < KEYSTONE_GROUP_TASK_MAX_STAGES; i++) {
    if (scheduler->stages[i].state != KEYSTONE_GROUP_STAGE_PENDING)
      continue;
    scheduler->stages[i].descriptor = *stage;
    scheduler->stages[i].state = KEYSTONE_GROUP_STAGE_RUNNABLE;
    return KEYSTONE_GROUP_TASK_OK;
  }
  return KEYSTONE_GROUP_TASK_ERR_FULL;
}

int keystone_group_task_submit(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_task_descriptor* task)
{
  size_t i;

  if (!scheduler || !task ||
      task->abi.version != KEYSTONE_ABI_VERSION ||
      task->abi.struct_size != sizeof(*task) ||
      !find_stage(scheduler, task->job_id, task->stage_id) ||
      task->input_bank >= KEYSTONE_YXSTM_MAX_BANKS ||
      task->output_bank >= KEYSTONE_YXSTM_MAX_BANKS || !task->length ||
      !task->commit_token ||
      (task->active_worker_mask & ~UINT64_C(0xe)) ||
      (task->preferred_lane_mask & ~UINT64_C(0xe)) ||
      !task_hard_lane_mask(scheduler, task) ||
      (task->deadline && scheduler->now && task->deadline <= scheduler->now))
    return KEYSTONE_GROUP_TASK_ERR_ARGUMENT;
  for (i = 0; i < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY; i++) {
    const struct keystone_group_task_slot* existing = &scheduler->tasks[i];
    if (existing->state == KEYSTONE_GROUP_TASK_STATE_FREE ||
        existing->descriptor.job_id != task->job_id ||
        existing->descriptor.stage_id != task->stage_id ||
        existing->descriptor.task_id != task->task_id ||
        existing->descriptor.partition_id != task->partition_id)
      continue;
    return existing->descriptor.commit_token == task->commit_token ?
        KEYSTONE_GROUP_TASK_OK : KEYSTONE_GROUP_TASK_ERR_COMMIT;
  }
  if (scheduler->queued_count + scheduler->running_count +
          scheduler->staged_count >=
      KEYSTONE_GROUP_TASK_QUEUE_CAPACITY)
    return KEYSTONE_GROUP_TASK_ERR_FULL;
  for (i = 0; i < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY; i++) {
    struct keystone_group_task_slot* slot = &scheduler->tasks[i];
    if (slot->state != KEYSTONE_GROUP_TASK_STATE_FREE)
      continue;
    memset(slot, 0, sizeof(*slot));
    slot->descriptor = *task;
    slot->state = KEYSTONE_GROUP_TASK_STATE_QUEUED;
    slot->assigned_lane = KEYSTONE_GROUP_TASK_NO_LANE;
    slot->submit_sequence = ++scheduler->submit_sequence;
    scheduler->queued_count++;
    if (!find_or_add_job(scheduler, task->job_id, task->weight)) {
      memset(slot, 0, sizeof(*slot));
      scheduler->queued_count--;
      return KEYSTONE_GROUP_TASK_ERR_FULL;
    }
    return KEYSTONE_GROUP_TASK_OK;
  }
  return KEYSTONE_GROUP_TASK_ERR_FULL;
}

int keystone_group_task_dispatch(
    struct keystone_group_task_scheduler* scheduler,
    struct keystone_group_task_descriptor* tasks,
    uint64_t* lane_ids, size_t capacity)
{
  size_t produced = 0;
  uint64_t reserved_mask = 0;

  if (!scheduler || !tasks || !lane_ids || !capacity)
    return KEYSTONE_GROUP_TASK_ERR_ARGUMENT;
  if (capacity > KEYSTONE_GROUP_TASK_MAX_LANES)
    capacity = KEYSTONE_GROUP_TASK_MAX_LANES;

  while (produced < capacity) {
    struct keystone_group_task_slot* selected = 0;
    size_t selected_index = 0;
    int lane_index;
    size_t i;

    for (i = 0; i < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY; i++) {
      struct keystone_group_task_slot* candidate = &scheduler->tasks[i];
      struct keystone_group_stage_slot* stage;

      if (!task_is_dispatchable(scheduler, candidate))
        continue;
      stage = find_stage(scheduler, candidate->descriptor.job_id,
                         candidate->descriptor.stage_id);
      if (stage && (stage->descriptor.flags &
                    KEYSTONE_GROUP_STAGE_FLAG_BARRIER)) {
        size_t available = 0;
        size_t queued = 0;
        size_t j;

        for (j = 0; j < KEYSTONE_GROUP_TASK_MAX_LANES; j++)
          if (!scheduler->lanes[j].busy &&
              (scheduler->active_worker_mask &
               (UINT64_C(1) << scheduler->lanes[j].lane_id)))
            available++;
        for (j = 0; j < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY; j++)
          if (task_is_dispatchable(scheduler, &scheduler->tasks[j]) &&
              scheduler->tasks[j].descriptor.job_id ==
                  candidate->descriptor.job_id &&
              scheduler->tasks[j].descriptor.stage_id ==
                  candidate->descriptor.stage_id)
            queued++;
        if (available < stage->descriptor.required_workers ||
            queued < stage->descriptor.required_workers ||
            capacity - produced < stage->descriptor.required_workers)
          continue;
      }
      if (fair_job_precedes(scheduler, candidate, selected)) {
        selected = candidate;
        selected_index = i;
      }
    }
    if (!selected)
      break;
    {
      struct keystone_group_stage_slot* stage =
          find_stage(scheduler, selected->descriptor.job_id,
                     selected->descriptor.stage_id);

      if (stage &&
          (stage->descriptor.flags & KEYSTONE_GROUP_STAGE_FLAG_BARRIER)) {
        size_t task_indices[KEYSTONE_GROUP_TASK_MAX_LANES];
        int lane_indices[KEYSTONE_GROUP_TASK_MAX_LANES];
        size_t required = (size_t)stage->descriptor.required_workers;
        size_t found = 0;
        uint64_t barrier_reserved = reserved_mask;
        size_t j;

        for (j = 0; j < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY &&
                    found < required; j++) {
          struct keystone_group_task_slot* candidate = &scheduler->tasks[j];
          int candidate_lane;

          if (!task_is_dispatchable(scheduler, candidate) ||
              candidate->descriptor.job_id != selected->descriptor.job_id ||
              candidate->descriptor.stage_id !=
                  selected->descriptor.stage_id)
            continue;
          candidate_lane = choose_lane(scheduler, &candidate->descriptor,
                                       barrier_reserved);
          if (candidate_lane < 0)
            continue;
          task_indices[found] = j;
          lane_indices[found] = candidate_lane;
          barrier_reserved |= UINT64_C(1) <<
              scheduler->lanes[candidate_lane].lane_id;
          found++;
        }
        if (found != required || produced + required > capacity)
          break;
        for (j = 0; j < required; j++) {
          dispatch_one(scheduler, task_indices[j], lane_indices[j],
                       &tasks[produced], &lane_ids[produced]);
          reserved_mask |= UINT64_C(1) << lane_ids[produced];
          produced++;
        }
        continue;
      }
    }
    lane_index = choose_lane(scheduler, &selected->descriptor,
                             reserved_mask);
    if (lane_index < 0)
      break;
    dispatch_one(scheduler, selected_index, lane_index,
                 &tasks[produced], &lane_ids[produced]);
    reserved_mask |= UINT64_C(1) << lane_ids[produced];
    produced++;
  }
  return (int)produced;
}

static int choose_prefetch_lane(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_task_descriptor* task,
    uint64_t reserved_mask)
{
  uint64_t hard_allowed = task_hard_lane_mask(scheduler, task);
  uint64_t allowed = task->preferred_lane_mask ?
      task->preferred_lane_mask & hard_allowed : hard_allowed;
  int fallback = -1;
  size_t i;

  for (i = 0; i < KEYSTONE_GROUP_TASK_MAX_LANES; i++) {
    struct keystone_group_task_lane* lane = &scheduler->lanes[i];
    uint64_t bit = UINT64_C(1) << lane->lane_id;

    if (!(allowed & bit) || (reserved_mask & bit) ||
        lane->prefetched_task_index != KEYSTONE_GROUP_TASK_QUEUE_CAPACITY)
      continue;
    if (lane->resident_bank == task->input_bank)
      return (int)i;
    if (fallback < 0)
      fallback = (int)i;
  }
  if (fallback >= 0)
    return fallback;
  allowed = hard_allowed;
  for (i = 0; i < KEYSTONE_GROUP_TASK_MAX_LANES; i++) {
    struct keystone_group_task_lane* lane = &scheduler->lanes[i];
    uint64_t bit = UINT64_C(1) << lane->lane_id;

    if ((allowed & bit) && !(reserved_mask & bit) &&
        lane->prefetched_task_index == KEYSTONE_GROUP_TASK_QUEUE_CAPACITY)
      return (int)i;
  }
  return -1;
}

int keystone_group_task_prefetch(
    struct keystone_group_task_scheduler* scheduler,
    struct keystone_group_task_descriptor* tasks,
    uint64_t* lane_ids, size_t capacity)
{
  size_t task_indices[KEYSTONE_GROUP_TASK_MAX_LANES];
  int lane_indices[KEYSTONE_GROUP_TASK_MAX_LANES];
  struct keystone_group_stage_slot* selected_stage = 0;
  uint64_t reserved_mask = 0;
  size_t required;
  size_t found = 0;
  size_t i;

  if (!scheduler || !tasks || !lane_ids || !capacity)
    return KEYSTONE_GROUP_TASK_ERR_ARGUMENT;
  if (capacity > KEYSTONE_GROUP_TASK_MAX_LANES)
    capacity = KEYSTONE_GROUP_TASK_MAX_LANES;
  for (i = 0; i < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY; i++) {
    struct keystone_group_task_slot* task = &scheduler->tasks[i];
    struct keystone_group_stage_slot* stage;

    if (!task_is_dispatchable(scheduler, task))
      continue;
    stage = find_stage(scheduler, task->descriptor.job_id,
                       task->descriptor.stage_id);
    if (stage && (stage->descriptor.flags &
                  KEYSTONE_GROUP_STAGE_FLAG_BARRIER)) {
      selected_stage = stage;
      break;
    }
  }
  if (!selected_stage)
    return 0;
  required = (size_t)selected_stage->descriptor.required_workers;
  if (required > capacity)
    return 0;
  for (i = 0; i < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY && found < required;
       i++) {
    struct keystone_group_task_slot* task = &scheduler->tasks[i];
    int lane_index;

    if (!task_is_dispatchable(scheduler, task) ||
        task->descriptor.job_id != selected_stage->descriptor.job_id ||
        task->descriptor.stage_id != selected_stage->descriptor.stage_id)
      continue;
    lane_index = choose_prefetch_lane(scheduler, &task->descriptor,
                                      reserved_mask);
    if (lane_index < 0)
      continue;
    task_indices[found] = i;
    lane_indices[found] = lane_index;
    reserved_mask |= UINT64_C(1) << scheduler->lanes[lane_index].lane_id;
    found++;
  }
  if (found != required)
    return 0;
  for (i = 0; i < required; i++) {
    struct keystone_group_task_slot* task =
        &scheduler->tasks[task_indices[i]];
    struct keystone_group_task_lane* lane =
        &scheduler->lanes[lane_indices[i]];

    task->state = KEYSTONE_GROUP_TASK_STATE_STAGED;
    task->assigned_lane = lane->lane_id;
    lane->prefetched_task_index = task_indices[i];
    scheduler->queued_count--;
    scheduler->staged_count++;
    tasks[i] = task->descriptor;
    lane_ids[i] = lane->lane_id;
  }
  return (int)required;
}

int keystone_group_task_activate_prefetched(
    struct keystone_group_task_scheduler* scheduler, uint64_t bank_id,
    struct keystone_group_task_descriptor* tasks,
    uint64_t* lane_ids, size_t capacity)
{
  size_t activated = 0;
  size_t i;

  if (!scheduler || !tasks || !lane_ids ||
      bank_id >= KEYSTONE_YXSTM_MAX_BANKS || !capacity)
    return KEYSTONE_GROUP_TASK_ERR_ARGUMENT;
  if (capacity > KEYSTONE_GROUP_TASK_MAX_LANES)
    capacity = KEYSTONE_GROUP_TASK_MAX_LANES;
  for (i = 0; i < KEYSTONE_GROUP_TASK_MAX_LANES && activated < capacity;
       i++) {
    struct keystone_group_task_lane* lane = &scheduler->lanes[i];
    struct keystone_group_task_slot* task;
    struct keystone_group_stage_slot* stage;
    struct keystone_group_task_job_fairness* job;

    if (lane->busy ||
        lane->prefetched_task_index >= KEYSTONE_GROUP_TASK_QUEUE_CAPACITY)
      continue;
    task = &scheduler->tasks[lane->prefetched_task_index];
    if (task->state != KEYSTONE_GROUP_TASK_STATE_STAGED ||
        task->descriptor.input_bank != bank_id)
      continue;
    task->state = KEYSTONE_GROUP_TASK_STATE_RUNNING;
    lane->busy = 1;
    lane->task_index = lane->prefetched_task_index;
    lane->prefetched_task_index = KEYSTONE_GROUP_TASK_QUEUE_CAPACITY;
    scheduler->staged_count--;
    scheduler->running_count++;
    scheduler->dispatch_sequence++;
    stage = find_stage(scheduler, task->descriptor.job_id,
                       task->descriptor.stage_id);
    if (stage)
      stage->state = KEYSTONE_GROUP_STAGE_RUNNING;
    job = find_or_add_job(scheduler, task->descriptor.job_id,
                          task->descriptor.weight);
    if (job) {
      uint64_t units = task->descriptor.length ? task->descriptor.length : 1;
      job->service_units = UINT64_MAX - job->service_units < units ?
          UINT64_MAX : job->service_units + units;
      if (scheduler->mode == KEYSTONE_GROUP_TASK_SCHED_ROUND_ROBIN)
        scheduler->rr_job_cursor =
            ((uint64_t)(job - scheduler->jobs) + 1) %
            KEYSTONE_GROUP_TASK_MAX_JOBS;
    }
    tasks[activated] = task->descriptor;
    lane_ids[activated] = lane->lane_id;
    activated++;
  }
  return (int)activated;
}

static struct keystone_group_task_slot* find_result_task(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_task_result* result)
{
  size_t i;

  for (i = 0; i < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY; i++) {
    struct keystone_group_task_slot* task = &scheduler->tasks[i];
    if (task->state != KEYSTONE_GROUP_TASK_STATE_FREE &&
        task->descriptor.job_id == result->job_id &&
        task->descriptor.stage_id == result->stage_id &&
        task->descriptor.task_id == result->task_id &&
        task->descriptor.partition_id == result->partition_id)
      return task;
  }
  return 0;
}

int keystone_group_task_complete(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_task_result* result)
{
  struct keystone_group_task_slot* task;
  int lane_index;

  if (!scheduler || !result)
    return KEYSTONE_GROUP_TASK_ERR_ARGUMENT;
  task = find_result_task(scheduler, result);
  if (!task)
    return KEYSTONE_GROUP_TASK_ERR_NOT_FOUND;
  if (task->state == KEYSTONE_GROUP_TASK_STATE_SUCCEEDED)
    return task->committed_token == result->commit_token &&
           task->result_digest == result->digest ?
        KEYSTONE_GROUP_TASK_OK : KEYSTONE_GROUP_TASK_ERR_COMMIT;
  if (task->state != KEYSTONE_GROUP_TASK_STATE_RUNNING ||
      task->descriptor.attempt_id != result->attempt_id ||
      task->descriptor.task_epoch != result->task_epoch ||
      task->descriptor.commit_token != result->commit_token ||
      task->assigned_lane != result->lane_id)
    return KEYSTONE_GROUP_TASK_ERR_STALE;
  lane_index = lane_index_from_id(task->assigned_lane);
  if (lane_index < 0 || !scheduler->lanes[lane_index].busy ||
      scheduler->lanes[lane_index].task_index !=
          (uint64_t)(task - scheduler->tasks))
    return KEYSTONE_GROUP_TASK_ERR_STATE;
  if (task->descriptor.flags & KEYSTONE_GROUP_TASK_FLAG_CANCELLED) {
    int timed_out = !!(task->descriptor.flags &
                       KEYSTONE_GROUP_TASK_FLAG_TIMED_OUT);
    task->state = timed_out ? KEYSTONE_GROUP_TASK_STATE_FAILED :
                              KEYSTONE_GROUP_TASK_STATE_CANCELLED;
    scheduler->lanes[lane_index].busy = 0;
    scheduler->lanes[lane_index].task_index =
        KEYSTONE_GROUP_TASK_QUEUE_CAPACITY;
    scheduler->running_count--;
    if (timed_out)
      scheduler->failed_count++;
    else
      scheduler->cancelled_count++;
    update_stage_completion(scheduler, task->descriptor.job_id,
                            task->descriptor.stage_id);
    return KEYSTONE_GROUP_TASK_OK;
  }
  task->state = KEYSTONE_GROUP_TASK_STATE_SUCCEEDED;
  task->result_digest = result->digest;
  task->committed_token = result->commit_token;
  scheduler->lanes[lane_index].busy = 0;
  scheduler->lanes[lane_index].task_index =
      KEYSTONE_GROUP_TASK_QUEUE_CAPACITY;
  scheduler->lanes[lane_index].resident_bank = task->descriptor.output_bank;
  scheduler->lanes[lane_index].completed_tasks++;
  scheduler->running_count--;
  scheduler->completed_count++;
  update_stage_completion(scheduler, task->descriptor.job_id,
                          task->descriptor.stage_id);
  return KEYSTONE_GROUP_TASK_OK;
}

int keystone_group_task_fail(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_task_result* result)
{
  struct keystone_group_task_slot* task;
  int lane_index;

  if (!scheduler || !result)
    return KEYSTONE_GROUP_TASK_ERR_ARGUMENT;
  task = find_result_task(scheduler, result);
  if (!task || task->state != KEYSTONE_GROUP_TASK_STATE_RUNNING ||
      task->descriptor.attempt_id != result->attempt_id)
    return KEYSTONE_GROUP_TASK_ERR_STALE;
  lane_index = lane_index_from_id(task->assigned_lane);
  if (lane_index >= 0) {
    scheduler->lanes[lane_index].busy = 0;
    scheduler->lanes[lane_index].task_index =
        KEYSTONE_GROUP_TASK_QUEUE_CAPACITY;
  }
  scheduler->running_count--;
  task->assigned_lane = KEYSTONE_GROUP_TASK_NO_LANE;
  if ((task->descriptor.flags & KEYSTONE_GROUP_TASK_FLAG_RETRYABLE) &&
      task->descriptor.attempt_id + 1 < task->descriptor.max_attempts) {
    task->descriptor.attempt_id++;
    task->retry_count++;
    task->state = KEYSTONE_GROUP_TASK_STATE_RETRY;
    task->submit_sequence = ++scheduler->submit_sequence;
    scheduler->queued_count++;
    return KEYSTONE_GROUP_TASK_OK;
  }
  task->state = KEYSTONE_GROUP_TASK_STATE_FAILED;
  scheduler->failed_count++;
  update_stage_completion(scheduler, task->descriptor.job_id,
                          task->descriptor.stage_id);
  return KEYSTONE_GROUP_TASK_ERR_STATE;
}

int keystone_group_task_cancel(
    struct keystone_group_task_scheduler* scheduler,
    uint64_t job_id, uint64_t stage_id, uint64_t task_id)
{
  size_t i;

  if (!scheduler)
    return KEYSTONE_GROUP_TASK_ERR_ARGUMENT;
  for (i = 0; i < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY; i++) {
    struct keystone_group_task_slot* task = &scheduler->tasks[i];
    if (task->state == KEYSTONE_GROUP_TASK_STATE_FREE ||
        task->descriptor.job_id != job_id ||
        task->descriptor.stage_id != stage_id ||
        task->descriptor.task_id != task_id)
      continue;
    if (task->state == KEYSTONE_GROUP_TASK_STATE_RUNNING) {
      task->descriptor.flags |= KEYSTONE_GROUP_TASK_FLAG_CANCELLED;
      return KEYSTONE_GROUP_TASK_OK;
    }
    if (task->state == KEYSTONE_GROUP_TASK_STATE_STAGED) {
      int lane_index = lane_index_from_id(task->assigned_lane);
      if (lane_index >= 0)
        scheduler->lanes[lane_index].prefetched_task_index =
            KEYSTONE_GROUP_TASK_QUEUE_CAPACITY;
      scheduler->staged_count--;
    }
    if (task->state == KEYSTONE_GROUP_TASK_STATE_QUEUED ||
        task->state == KEYSTONE_GROUP_TASK_STATE_RETRY)
      scheduler->queued_count--;
    task->state = KEYSTONE_GROUP_TASK_STATE_CANCELLED;
    task->descriptor.flags |= KEYSTONE_GROUP_TASK_FLAG_CANCELLED;
    scheduler->cancelled_count++;
    update_stage_completion(scheduler, job_id, stage_id);
    memset(task, 0, sizeof(*task));
    task->assigned_lane = KEYSTONE_GROUP_TASK_NO_LANE;
    return KEYSTONE_GROUP_TASK_OK;
  }
  return KEYSTONE_GROUP_TASK_ERR_NOT_FOUND;
}

int keystone_group_task_advance_time(
    struct keystone_group_task_scheduler* scheduler, uint64_t now)
{
  size_t i;

  if (!scheduler || now < scheduler->now)
    return KEYSTONE_GROUP_TASK_ERR_ARGUMENT;
  scheduler->now = now;
  for (i = 0; i < KEYSTONE_GROUP_TASK_QUEUE_CAPACITY; i++) {
    struct keystone_group_task_slot* task = &scheduler->tasks[i];
    int lane_index;

    if (task->state == KEYSTONE_GROUP_TASK_STATE_FREE ||
        !task->descriptor.deadline || task->descriptor.deadline > now ||
        (task->descriptor.flags & KEYSTONE_GROUP_TASK_FLAG_TIMED_OUT))
      continue;
    task->descriptor.flags |= KEYSTONE_GROUP_TASK_FLAG_CANCELLED |
                              KEYSTONE_GROUP_TASK_FLAG_TIMED_OUT;
    scheduler->deadline_expired_count++;
    if (task->state == KEYSTONE_GROUP_TASK_STATE_RUNNING)
      continue;
    if (task->state == KEYSTONE_GROUP_TASK_STATE_STAGED) {
      lane_index = lane_index_from_id(task->assigned_lane);
      if (lane_index >= 0)
        scheduler->lanes[lane_index].prefetched_task_index =
            KEYSTONE_GROUP_TASK_QUEUE_CAPACITY;
      scheduler->staged_count--;
    } else if (task->state == KEYSTONE_GROUP_TASK_STATE_QUEUED ||
               task->state == KEYSTONE_GROUP_TASK_STATE_RETRY) {
      scheduler->queued_count--;
    } else {
      continue;
    }
    task->state = KEYSTONE_GROUP_TASK_STATE_FAILED;
    task->assigned_lane = KEYSTONE_GROUP_TASK_NO_LANE;
    scheduler->failed_count++;
    update_stage_completion(scheduler, task->descriptor.job_id,
                            task->descriptor.stage_id);
  }
  return KEYSTONE_GROUP_TASK_OK;
}

int keystone_group_task_stage_state(
    const struct keystone_group_task_scheduler* scheduler,
    uint64_t job_id, uint64_t stage_id, uint64_t* state)
{
  size_t i;

  if (!scheduler || !state)
    return KEYSTONE_GROUP_TASK_ERR_ARGUMENT;
  for (i = 0; i < KEYSTONE_GROUP_TASK_MAX_STAGES; i++)
    if (scheduler->stages[i].state != KEYSTONE_GROUP_STAGE_PENDING &&
        scheduler->stages[i].descriptor.job_id == job_id &&
        scheduler->stages[i].descriptor.stage_id == stage_id) {
      *state = scheduler->stages[i].state;
      return KEYSTONE_GROUP_TASK_OK;
    }
  return KEYSTONE_GROUP_TASK_ERR_NOT_FOUND;
}

int keystone_group_task_idle(
    const struct keystone_group_task_scheduler* scheduler)
{
  return scheduler && !scheduler->queued_count &&
         !scheduler->running_count && !scheduler->staged_count;
}
