#!/usr/bin/env python3
"""Exercise actual driver handoff functions with an immediate Host ACK interleaving."""

import os
import pathlib
import re
import subprocess
import tempfile


def function(source, name):
    match = re.search(r"^(?:static\s+)?(?:inline\s+)?"
                      r"(?:void|bool|int|unsigned int|unsigned long)\s+" + name +
                      r"\([^;{}]*?\)\s*\{", source, re.MULTILINE)
    if not match:
        raise RuntimeError("Function definition not found: " + name)
    depth = 1
    end = match.end()
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


PRELUDE = r'''
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#define CONFIG_RISCV_HSM_CPU_LEASE 1
#define IS_ENABLED(value) (value)
#define KEYSTONE_GROUP_DRIVER_MAX_WORKERS 3
#define KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE 1
#define KEYSTONE_GROUP_EVENT_OCALL 1
#define KEYSTONE_GROUP_EVENT_WORKERS_READY 2
#define KEYSTONE_GROUP_EVENT_EXITED 3
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, data) ((value) = (data))
#define smp_rmb() std::atomic_thread_fence(std::memory_order_acquire)
#define smp_wmb() std::atomic_thread_fence(std::memory_order_release)
#define smp_mb__after_atomic() std::atomic_thread_fence(std::memory_order_seq_cst)
#define container_of(ptr, type, member) \
    reinterpret_cast<type*>(reinterpret_cast<char*>(ptr) - offsetof(type, member))
using atomic_t = std::atomic<int>;
using atomic_long_t = std::atomic<long>;
static int atomic_read(atomic_t* a) { return a->load(); }
static int atomic_read_acquire(atomic_t* a) { return a->load(std::memory_order_acquire); }
static void atomic_set(atomic_t* a, int v) { a->store(v); }
static void atomic_set_release(atomic_t* a, int v) { a->store(v, std::memory_order_release); }
static long atomic_long_read(atomic_long_t* a) { return a->load(); }
static void atomic_long_set(atomic_long_t* a, long v) { a->store(v); }
static long atomic_long_cmpxchg(atomic_long_t* a, long old, long next) {
    a->compare_exchange_strong(old, next);
    return old;
}
struct work_struct {};
struct keystone_group_run_hart {
    unsigned long event = 0, event_sequence = 0, eid = 0, hart_id = 0;
};
struct keystone_group_driver_context;
struct keystone_group_worker_runner {
    keystone_group_driver_context* group = nullptr;
    unsigned long hart_id = 0, hsm_commit_event = 0, hsm_commit_eid = 0;
    atomic_t hsm_event_pending{0};
    atomic_long_t hsm_commit_pending_sequence{0}, hsm_commit_acked_sequence{0};
    unsigned int wake_sequence = 0;
    keystone_group_run_hart hsm_event;
};
struct keystone_group_driver_context {
    atomic_t stop_requested{0};
    bool leased = true;
    unsigned long lease_flags = KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE;
    struct { unsigned int housekeeping_cpu = 0; } topology;
    keystone_group_worker_runner workers[KEYSTONE_GROUP_DRIVER_MAX_WORKERS];
    work_struct hsm_event_work;
};
static keystone_group_driver_context* current;
static int notifications, delivered, waits, signals;
static unsigned long delivered_sequence;
static bool immediate_ack, publish_next, parked;
static unsigned int parked_sequence;
struct MailboxWait {};
static keystone_group_driver_context* keystone_group_context(unsigned long id) {
    return id == 1 ? current : nullptr;
}
static unsigned int keystone_group_hsm_wake_snapshot(keystone_group_worker_runner* r) {
    return r->wake_sequence;
}
static void keystone_group_hsm_prepare_wait() {}
static void keystone_group_hsm_wait(keystone_group_worker_runner* r, unsigned int observed) {
    if (r->group->stop_requested.load() || observed != r->wake_sequence)
        return;
    ++waits;
    parked = true;
    parked_sequence = observed;
    throw MailboxWait();
}
static void keystone_group_hsm_signal_runner(keystone_group_worker_runner* r) {
    ++signals;
    ++r->wake_sequence;
}
static int riscv_hsm_cpu_lease_notify(unsigned int cpu) {
    if (cpu != 0) std::abort();
    ++notifications;
    return 0;
}
static void keystone_group_translate_event(keystone_group_run_hart* event) {
    event->eid += 4096;
}
static void keystone_group_push_event(keystone_group_driver_context*,
                                      const keystone_group_run_hart*);
'''

TEST = r'''
static void require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}
static void keystone_group_push_event(keystone_group_driver_context* context,
                                      const keystone_group_run_hart* event) {
    ++delivered;
    delivered_sequence = event->event_sequence;
    auto* runner = &context->workers[event->hart_id - 2];
    if (!immediate_ack || !keystone_group_hsm_event_needs_host_commit(event->event))
        return;
    require(runner->hsm_commit_pending_sequence.load() ==
                static_cast<long>(event->event_sequence), "ACK metadata must precede visibility");
    keystone_group_commit_event(1, event->event, event->hart_id, event->eid);
    require(runner->hsm_commit_acked_sequence.exchange(0) ==
                static_cast<long>(event->event_sequence), "Host ACK sequence");
    keystone_group_hsm_signal_runner(runner);
    if (!publish_next) return;
    keystone_group_run_hart next = *event;
    next.eid -= 4096;
    ++next.event_sequence;
    try {
        // Host preempts the consumer, ACKs, and the remote hart publishes again.
        keystone_group_hsm_publish_event(runner, &next);
    } catch (const MailboxWait&) {
        // The consumer can continue, but must not strand the producer in WFI.
    }
}
int main() {
    for (unsigned int lane = 0; lane != 3; ++lane) {
        for (unsigned long type : {1UL, 2UL, 3UL}) {
            for (bool early : {false, true}) {
                keystone_group_driver_context context;
                current = &context;
                for (unsigned int i = 0; i != 3; ++i) {
                    context.workers[i].group = &context;
                    context.workers[i].hart_id = i + 2;
                }
                notifications = delivered = waits = signals = 0;
                parked = false;
                immediate_ack = early;
                publish_next = true;
                auto* runner = &context.workers[lane];
                keystone_group_run_hart event;
                event.event = type;
                event.event_sequence = 41;
                event.eid = lane + 1;
                event.hart_id = lane + 2;
                keystone_group_hsm_publish_event(runner, &event);
                keystone_group_hsm_event_work(&context.hsm_event_work);
                require(delivered == 1 && delivered_sequence == 41, "deliver original exactly once");
                require(!(parked && parked_sequence == runner->wake_sequence),
                        "early ACK strands the next producer after mailbox clear (lost wake)");
                if (early && type != KEYSTONE_GROUP_EVENT_EXITED) {
                    require(waits == 0 && runner->hsm_event_pending.load() == 1,
                            "next event must survive the old consumer");
                    require(notifications == 2 && signals == 1, "no polling or extra ACK wake");
                    publish_next = false;
                    keystone_group_hsm_event_work(&context.hsm_event_work);
                    require(delivered == 2 && delivered_sequence == 42 &&
                            runner->hsm_event_pending.load() == 0, "deliver next event exactly once");
                } else {
                    require(runner->hsm_event_pending.load() == 0, "mailbox released");
                    require(signals == (type == KEYSTONE_GROUP_EVENT_EXITED ? 1 : 0),
                            "mailbox release must not manufacture a Host commit");
                    if (type != KEYSTONE_GROUP_EVENT_EXITED) {
                        keystone_group_commit_event(1, type, event.hart_id, event.eid + 4096);
                        require(runner->hsm_commit_acked_sequence.load() == 41, "late ACK preserved");
                    }
                }
            }
        }
    }
    std::puts("HSM mailbox handoff PASS: early/late ACK, next publication, three lanes, no extra wake");
}
'''


def main():
    root = pathlib.Path(__file__).resolve().parents[3]
    source = (root / "linux-keystone-driver/keystone-group.c").read_text()
    names = ["keystone_group_hsm_event_needs_host_commit",
             "keystone_group_hsm_publish_event", "keystone_group_commit_event",
             "keystone_group_hsm_event_work"]
    unit = PRELUDE + "\n".join(function(source, name) for name in names) + TEST
    with tempfile.TemporaryDirectory(prefix="keystone-hsm-handoff-") as directory:
        binary = pathlib.Path(directory) / "handoff"
        subprocess.run([os.environ.get("CXX", "g++"), "-std=c++11", "-O2",
                        "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                        "-pthread", "-x", "c++", "-o", str(binary), "-"],
                       input=unit, text=True, check=True)
        subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == "__main__":
    main()
