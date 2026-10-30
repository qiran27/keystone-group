import importlib.util
from pathlib import Path

path = Path(__file__).resolve().parents[1] / 'analyze-sqlite-neighbors.py'
spec = importlib.util.spec_from_file_location('neighbor_audit', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def trace(offset=4096, arrival=2, ready=3, submit=8, plan=2, io=2):
    rows = []
    for worker, off, a, r, s, p, token in [(0, 0, 1, 2, 7, 1, 1),
                                         (1, offset, arrival, ready, submit, plan, io)]:
        for event, time in [('queue_enqueue', a), ('neighbor_plan_ready', r), ('neighbor_submit', s)]:
            rows.append(dict(case_id='1', sample_id='1', case_io_mode='adaptive-extent',
                case_workload='7', case_worker_count='2', request_sample_stride='1',
                request_events_omitted='0', event=event, operation='read', run_id=str(worker+1),
                worker_index=str(worker), request_id='1', buffer_id='0', sequence='1', task_id='1',
                timestamp_ns=str(time), file_id='1', file_offset=str(off), length='4096',
                request_workload='7', result='2', queue_depth=str(p), value=str(token)))
    rows.append(dict(rows[-1], event='case_end'))
    return rows


r = module.audit_case(trace())
assert r['complete_trace'] and r['cross_plan_separate_io_pairs'] == 1
assert module.audit_case(trace(ready=7))['co_pending_but_not_co_planned'] == 1
assert module.audit_case(trace(arrival=8, ready=8, submit=9))['never_co_pending'] == 1
assert module.audit_case(trace(plan=1))['co_planned_same_plan'] == 1
assert module.audit_case(trace(submit=7, io=1))['same_io_adjacent_pairs'] == 1
assert module.audit_case(trace(offset=8192))['adjacent_pairs'] == 0
rows = trace()
for row in rows:
    if row['event']=='neighbor_plan_ready':
        row['result'] = '230' if row['worker_index']=='0' else '618'
assert module.audit_case(rows)['adjacent_pairs'] == 1
for row in rows:
    if row['event']=='neighbor_plan_ready' and row['worker_index']=='1':
        row['result'] = '1'  # PREFILL is not compatible with MEASURED.
assert module.audit_case(rows)['adjacent_pairs'] == 0
rows = trace(ready=8, submit=9)
rows.append(dict(rows[-1], event='neighbor_submit_batch', timestamp_ns='7', value='1', result='1'))
rows.append(dict(rows[-1], timestamp_ns='9'))
r = module.audit_case(rows)
assert r['complete_trace'] and r['submit_batches'] == 2 and r['enter_calls'] == 2
assert r['batches_with_queued_unplanned_requests'] == 1
assert r['submission_examples'][0]['planned_pending_requests_including_batch'] == 1
assert r['batches_leaving_planned_requests'] == 0
assert not module.audit_case(trace())['submission_diagnostic_available']
assert not module.audit_case(trace()[1:])['complete_trace']
rows = trace()
rows[0]['request_events_omitted'] = '1'
assert not module.audit_case(rows)['complete_trace']
assert not module.audit_case(trace(), pair_limit=0)['complete_trace']
rows = trace()
rows[-1]['event'] = 'case_abort'
assert not module.audit_case(rows)['complete_trace']
print('Neighbor audit: actual arrival/plan/submit windows, cross-plan pairs, sparse, sampled/missing/aborted/capped traces PASS')

def trace_v2():
    rows = trace(ready=8, submit=9)
    for row in rows:
        row.update(diagnostic_version='2', events_dropped='0', completion_id=row['worker_index'])
        if row['event']=='case_end': row['timestamp_ns']='20'
    rows.append(dict(rows[3], event='neighbor_admission', timestamp_ns='6', result='4',
                     **{k:'1' for k in module.STATE_FIELDS}))
    for index, submit in [(0,7),(3,9)]:
        rows.append(dict(rows[index],event='neighbor_submit_batch',timestamp_ns=str(submit),value='1',result='1'))
        rows.append(dict(rows[index],event='io_complete',timestamp_ns=str(submit+3),result='0'))
        rows.append(dict(rows[index],event='completion_publish',timestamp_ns=str(submit+4),result='0'))
    return rows

rows = trace_v2()
r = module.audit_case(rows)
assert r['complete_trace'] and r['lifecycle_complete'] and r['accepted_matches_attempted']
assert r['admission_reason_counts']['sqe_credit'] == 1
assert len(r['co_pending_rejection_evidence']) == 1
assert r['request_latency']['io_complete_to_publish']['p95_ns'] == 1
rows[0]['events_dropped'] = '1'
assert not module.audit_case(rows)['complete_trace']
rows = trace_v2()
rows[-1]['result'] = '-5'
assert not module.audit_case(rows)['complete_trace']
assert not module.audit_case(trace_v2()[:-1])['complete_trace']
rows = trace_v2()
for row in rows:
    if row['event']=='neighbor_submit_batch': row['value']='0'
assert not module.audit_case(rows)['complete_trace']
print('Neighbor admission v2: credit evidence, completion latency, dropped/failed/partial rejection PASS')
