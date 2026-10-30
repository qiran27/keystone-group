#!/usr/bin/env python3
"""Run actual SM kick and driver idle functions with injected wake races."""

import os
from pathlib import Path
import subprocess
import tempfile

from importlib.util import spec_from_file_location, module_from_spec


here = Path(__file__).resolve().parent
project = here.parents[2]
spec = spec_from_file_location("handoff", here / "check-hsm-mailbox-handoff.py")
handoff = module_from_spec(spec)
spec.loader.exec_module(handoff)
driver = (project / "linux-keystone-driver/keystone-group.c").read_text()
sm = (project / "sm/src/ipi.c").read_text()
prepare_name = "keystone_group_hsm_prepare_wait"
prepare = (handoff.function(driver, prepare_name) if prepare_name in driver
           else "static void keystone_group_hsm_prepare_wait(void) {}")
wait = handoff.function(driver, "keystone_group_hsm_wait")
wait = wait.replace('__asm__ __volatile__("wfi" ::: "memory");', 'test_wfi();')
assert "test_wfi();" in wait

prelude = r'''
#include <cassert>
#include <cstdio>
#include <cstdlib>
struct sbi_scratch {};
struct Context { int stop_requested = 0; };
struct keystone_group_worker_runner { Context* group; unsigned sequence = 0; };
static unsigned ip, ie, status;
static bool enclave, work_ready, parked;
static void (*before_wfi)();
#define CSR_STATUS 0
#define CSR_IE 1
#define CSR_IP 2
#define mip 2
#define SR_IE 2
#define IE_SIE 2
#define MIP_SSIP 2
#define smp_mb() ((void)0)
static unsigned& csr(unsigned n) { return n == 0 ? status : (n == 1 ? ie : ip); }
#define csr_read(n) csr(n)
#define csr_set(n, bits) (csr(n) |= (bits))
#define csr_clear(n, bits) (csr(n) &= ~(bits))
static int cpu_is_enclave_context() { return enclave; }
static int atomic_read(int* p) { return *p; }
static unsigned keystone_group_hsm_wake_snapshot(keystone_group_worker_runner* r) {
  return r->sequence;
}
static void test_wfi() {
  if (before_wfi) before_wfi();
  parked = !(ip & ie & IE_SIE);
}
static void require(bool value, const char* message) {
  if (!value) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
'''
tests = r'''
static void ready_kick() {
  work_ready = true;
  group_scheduler_kick_process(nullptr);
}
int main() {
  Context context;
  keystone_group_worker_runner runner{&context};
  // No HOST ACK: only the SM knows that a slot has become READY.
  for (int boundary = 0; boundary != 3; ++boundary) {
    ip = ie = status = 0;
    enclave = work_ready = parked = false;
    before_wfi = nullptr;
    keystone_group_hsm_prepare_wait();
    unsigned observed = runner.sequence;
    if (boundary == 0) ready_kick(); // before the authoritative runqueue check
    bool runnable = work_ready;
    if (boundary == 1) ready_kick(); // after NOT_RUNNABLE, before wait()
    if (boundary == 2) before_wfi = ready_kick; // check-to-WFI race
    if (!runnable) keystone_group_hsm_wait(&runner, observed);
    require(!parked, "SM READY kick lost at the leased hart idle boundary");
  }
  ip = IE_SIE;
  before_wfi = nullptr;
  keystone_group_hsm_prepare_wait();
  require(!ip, "old SSIP must be cleared before testing the level condition");
  keystone_group_hsm_wait(&runner, runner.sequence);
  require(parked, "an idle lane must sleep, not busy-poll");
  parked = false;
  ++runner.sequence;
  keystone_group_hsm_wait(&runner, runner.sequence - 1);
  require(!parked, "early HOST ACK must prevent sleep");
  enclave = true; ip = 0;
  group_scheduler_kick_process(nullptr);
  require(!ip, "enclave kick must not leak an SSIP into the runtime");
  std::puts("HSM idle wake PASS: READY before/after query, check-to-WFI, HOST ACK, no busy loop");
}
'''

with tempfile.TemporaryDirectory(prefix="keystone-hsm-idle-") as tmp:
    source = Path(tmp) / "test.cpp"
    binary = Path(tmp) / "test"
    source.write_text(prelude + handoff.function(sm, "group_scheduler_kick_process") +
                      prepare + wait + tests)
    subprocess.run([os.environ.get("CXX", "g++"), "-std=c++14", "-O2",
                    "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                    str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

# The durable condition must be inspected only after consuming an old edge.
lease = handoff.function(driver, "keystone_group_hsm_lease_enter")
for block in (lease.split("while (!atomic_read(&runner->hsm_run_enabled)", 1)[1],
              lease.split("while (!atomic_read(&context->stop_requested))", 1)[1]):
    assert block.index(prepare_name + "();") < block.index(
        "keystone_group_hsm_wake_snapshot(runner)")
assert "csr_clear(CSR_IP" not in wait
