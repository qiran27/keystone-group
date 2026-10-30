#ifndef GROUP_PMP_SQLITE_PIPELINE_TIMING_H
#define GROUP_PMP_SQLITE_PIPELINE_TIMING_H

#include <stdint.h>

/* Per-worker rdtime intervals. These overlap and must not be summed as wall
 * time. Host completion timestamps are diagnostic, never authorization. */
struct group_pmp_sqlite_pipeline_timing {
  uint64_t doorbell_count;
  uint64_t doorbell_ack_ticks;
  uint64_t doorbell_ack_max_ticks;
  uint64_t completion_to_consume_count;
  uint64_t completion_to_consume_ticks;
  uint64_t completion_to_consume_max_ticks;
  uint64_t completion_timestamp_invalid;
  uint64_t ack_to_consume_ticks;
  uint64_t ack_to_consume_max_ticks;
  uint64_t buffer_consume_count;
  uint64_t buffer_consume_ticks;
  uint64_t buffer_consume_max_ticks;
  uint64_t buffer_refill_count;
  uint64_t buffer_refill_ticks;
  uint64_t buffer_refill_max_ticks;
  uint64_t request_prepare_ticks;
  uint64_t submission_timing_count;
  uint64_t submission_timestamp_invalid;
  uint64_t submit_to_host_ticks;
  uint64_t submit_to_host_max_ticks;
  uint64_t host_to_ack_ticks;
  uint64_t host_to_ack_max_ticks;
  uint64_t ack_to_resume_request_ticks;
  uint64_t ack_to_resume_request_max_ticks;
  uint64_t resume_request_to_return_ticks;
  uint64_t resume_request_to_return_max_ticks;
  uint64_t wait_timing_count;
  uint64_t wait_timestamp_invalid;
  uint64_t wait_submit_to_host_ticks;
  uint64_t wait_host_to_resume_ticks;
  uint64_t wait_resume_to_return_ticks;
  uint64_t wait_resume_to_return_max_ticks;
  uint64_t wait_oncpu_ticks;
  uint64_t wait_offcpu_ticks;
  uint64_t wait_clock_invalid;
};

static inline void group_pmp_sqlite_pipeline_add(
    struct group_pmp_sqlite_pipeline_timing* total,
    const struct group_pmp_sqlite_pipeline_timing* value) {
  total->doorbell_count += value->doorbell_count;
  total->doorbell_ack_ticks += value->doorbell_ack_ticks;
  if (value->doorbell_ack_max_ticks > total->doorbell_ack_max_ticks)
    total->doorbell_ack_max_ticks = value->doorbell_ack_max_ticks;
  total->completion_to_consume_count += value->completion_to_consume_count;
  total->completion_to_consume_ticks += value->completion_to_consume_ticks;
  if (value->completion_to_consume_max_ticks > total->completion_to_consume_max_ticks)
    total->completion_to_consume_max_ticks = value->completion_to_consume_max_ticks;
  total->completion_timestamp_invalid += value->completion_timestamp_invalid;
  total->ack_to_consume_ticks += value->ack_to_consume_ticks;
  if (value->ack_to_consume_max_ticks > total->ack_to_consume_max_ticks)
    total->ack_to_consume_max_ticks = value->ack_to_consume_max_ticks;
  total->buffer_consume_count += value->buffer_consume_count;
  total->buffer_consume_ticks += value->buffer_consume_ticks;
  if (value->buffer_consume_max_ticks > total->buffer_consume_max_ticks)
    total->buffer_consume_max_ticks = value->buffer_consume_max_ticks;
  total->buffer_refill_count += value->buffer_refill_count;
  total->buffer_refill_ticks += value->buffer_refill_ticks;
  if (value->buffer_refill_max_ticks > total->buffer_refill_max_ticks)
    total->buffer_refill_max_ticks = value->buffer_refill_max_ticks;
  total->request_prepare_ticks += value->request_prepare_ticks;
  total->submission_timing_count += value->submission_timing_count;
  total->submission_timestamp_invalid += value->submission_timestamp_invalid;
  total->submit_to_host_ticks += value->submit_to_host_ticks;
  if (value->submit_to_host_max_ticks > total->submit_to_host_max_ticks)
    total->submit_to_host_max_ticks = value->submit_to_host_max_ticks;
  total->host_to_ack_ticks += value->host_to_ack_ticks;
  if (value->host_to_ack_max_ticks > total->host_to_ack_max_ticks)
    total->host_to_ack_max_ticks = value->host_to_ack_max_ticks;
  total->ack_to_resume_request_ticks += value->ack_to_resume_request_ticks;
  if (value->ack_to_resume_request_max_ticks > total->ack_to_resume_request_max_ticks)
    total->ack_to_resume_request_max_ticks = value->ack_to_resume_request_max_ticks;
  total->resume_request_to_return_ticks += value->resume_request_to_return_ticks;
  if (value->resume_request_to_return_max_ticks > total->resume_request_to_return_max_ticks)
    total->resume_request_to_return_max_ticks = value->resume_request_to_return_max_ticks;
  total->wait_timing_count += value->wait_timing_count;
  total->wait_timestamp_invalid += value->wait_timestamp_invalid;
  total->wait_submit_to_host_ticks += value->wait_submit_to_host_ticks;
  total->wait_host_to_resume_ticks += value->wait_host_to_resume_ticks;
  total->wait_resume_to_return_ticks += value->wait_resume_to_return_ticks;
  if (value->wait_resume_to_return_max_ticks > total->wait_resume_to_return_max_ticks)
    total->wait_resume_to_return_max_ticks = value->wait_resume_to_return_max_ticks;
  total->wait_oncpu_ticks += value->wait_oncpu_ticks;
  total->wait_offcpu_ticks += value->wait_offcpu_ticks;
  total->wait_clock_invalid += value->wait_clock_invalid;
}

static inline void group_pmp_sqlite_pipeline_wait(
    struct group_pmp_sqlite_pipeline_timing* stats, uint64_t submitted,
    uint64_t received, uint64_t ack, uint64_t resume, uint64_t returned) {
  if (!received || !ack || !resume || received < submitted ||
      ack < received || resume < ack || returned < resume) {
    ++stats->wait_timestamp_invalid;
    return;
  }
  ++stats->wait_timing_count;
  stats->wait_submit_to_host_ticks += received - submitted;
  stats->wait_host_to_resume_ticks += resume - received;
  stats->wait_resume_to_return_ticks += returned - resume;
  if (returned - resume > stats->wait_resume_to_return_max_ticks)
    stats->wait_resume_to_return_max_ticks = returned - resume;
}

static inline void group_pmp_sqlite_pipeline_submission(
    struct group_pmp_sqlite_pipeline_timing* stats, uint64_t submitted,
    uint64_t received, uint64_t ack, uint64_t resume, uint64_t returned) {
  if (!received || !ack || !resume || received < submitted ||
      ack < received || resume < ack || returned < resume) {
    ++stats->submission_timestamp_invalid;
    return;
  }
  ++stats->submission_timing_count;
  stats->submit_to_host_ticks += received - submitted;
  if (received - submitted > stats->submit_to_host_max_ticks)
    stats->submit_to_host_max_ticks = received - submitted;
  stats->host_to_ack_ticks += ack - received;
  if (ack - received > stats->host_to_ack_max_ticks)
    stats->host_to_ack_max_ticks = ack - received;
  stats->ack_to_resume_request_ticks += resume - ack;
  if (resume - ack > stats->ack_to_resume_request_max_ticks)
    stats->ack_to_resume_request_max_ticks = resume - ack;
  stats->resume_request_to_return_ticks += returned - resume;
  if (returned - resume > stats->resume_request_to_return_max_ticks)
    stats->resume_request_to_return_max_ticks = returned - resume;
}

#endif
