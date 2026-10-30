#!/usr/bin/env python3
"""Execute the actual SM resume blocks with mocked CSR/context operations."""

import os
import pathlib
import re
import subprocess
import tempfile


def braced(source, start):
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def function(source, name):
    match = re.search(r"^(?:static )?(?:inline )?[^\n]+ " + name +
                      r"\([^;]*?\)\s*\{", source, re.MULTILINE)
    if not match:
        raise RuntimeError("Function definition not found: " + name)
    return braced(source, match.start())


PRELUDE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned int enclave_id;
struct sbi_trap_regs { uintptr_t mepc, a0, a1; };
struct thread_state { struct sbi_trap_regs saved; };
struct thread_state_profile { unsigned long smode_csr_cycles; };
static struct { struct thread_state threads[1]; unsigned long group_id; } enclaves[2];
static int group_member_saved_mepc_advanced[2];
#define CSR_MCYCLE 0
#define SBI_ERR_SM_ENCLAVE_SUCCESS 0
#define GROUP_SCHED_RUNNABLE 1
static unsigned long csr_read(int ignored) { (void)ignored; return 0; }
static void group_scheduler_restore_thread_context_profiled(
    struct thread_state *t, struct sbi_trap_regs *r, struct thread_state_profile *p) {
  (void)p; *r = t->saved;
}
static void group_scheduler_restore_thread_context_exact(
    struct thread_state *t, struct sbi_trap_regs *r) { *r = t->saved; }
static void group_scheduler_prepare_first_run_regs(enclave_id eid, struct sbi_trap_regs *r) {
  (void)eid; r->mepc = 0x90000000; r->a0 = 0; r->a1 = 0x1234;
}
static void group_scheduler_schedule_in_local(enclave_id eid, int fast) { (void)eid; (void)fast; }
static void platform_switch_to_enclave(void *e) { (void)e; }
static int group_scheduler_switch_active_local(enclave_id e, enclave_id *n, int s, int a, int *f) {
  (void)e; (void)n; (void)s; (void)a; (void)f; return 0;
}
static void group_scheduler_restore_fresh_state(enclave_id e) { (void)e; }
static void check(int condition, const char *message) {
  if (!condition) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}
'''


def resume_wrapper(body, name):
    start = body.rindex("  if (next_first_run) {")
    end = body.index("  cpu_enter_enclave_context(next);", start)
    block = body[start:end].replace("  resume_mepc = regs->mepc;\n", "")
    return r'''
static uintptr_t NAME(int exact, uintptr_t pc, int next_first_run) {
  enclave_id next = 1;
  struct sbi_trap_regs result = {0}, *regs = &result;
  struct thread_state_profile restore_profile = {0};
  unsigned long component_start = 0;
  group_member_saved_mepc_advanced[next] = exact;
  enclaves[next].threads[0].saved = (struct sbi_trap_regs){pc, 0, 0x1234};
BLOCK
  check(result.a0 == 0 && result.a1 == 0x1234, "resume clobbers SBI return registers");
  check(group_member_saved_mepc_advanced[next] == 0, "resume flag not consumed");
  return result.mepc;
}
'''.replace("NAME", name).replace("BLOCK", block)


def host_wrapper(body):
    start = body.index("  } else if (enclaves[eid].group_id != 0")
    end = body.index("\n  switch_vector_enclave();", start)
    block = "  if (0) {\n" + body[start:end]
    return r'''
static uintptr_t host_resume(int exact, uintptr_t pc) {
  enclave_id eid = 1;
  struct sbi_trap_regs result = {pc, 0, 0x1234}, *regs = &result;
  enclaves[eid].group_id = 1;
  group_member_saved_mepc_advanced[eid] = exact;
BLOCK
  /* sbi_sm_group_run_hart / sbi_sm_resume_enclave wrapper. */
  regs->mepc += 4;
  check(result.a0 == 0 && result.a1 == 0x1234, "host resume clobbers registers");
  return result.mepc;
}
'''.replace("BLOCK", block)


def rollback_wrappers(body):
    result = ""
    index = 0
    for match in re.finditer(r"  if \(ret != SBI_ERR_SM_ENCLAVE_SUCCESS\) \{", body):
        block = braced(body, match.start())
        if "group_scheduler_restore_thread_context_exact" not in block:
            continue
        result += r'''
static uintptr_t rollback_INDEX(int advance_current_mepc) {
  enclave_id current = 0, next = 1;
  int same_lane_fast_path = 1, next_first_run = 0, ret = 1;
  struct sbi_trap_regs result = {0}, *regs = &result;
  (void)next; (void)next_first_run;
  enclaves[current].threads[0].saved = (struct sbi_trap_regs){
      0x11d8 + (advance_current_mepc ? 4 : 0), 0, 0x1234};
BLOCK
  abort();
}
'''.replace("INDEX", str(index)).replace("BLOCK", block.replace("return 0;", "return regs->mepc;"))
        index += 1
    if index != 2:
        raise RuntimeError("Expected both direct-ecall rollback blocks")
    return result


MAIN = r'''
int main(void) {
  uintptr_t (*paths[])(int, uintptr_t, int) = {ecall_resume, timer_resume};
  for (unsigned int p = 0; p < 2; ++p) {
    check(paths[p](0, 0x11d8, 0) == 0x11dc,
          "Host-completed OCALL selected by peer re-executes STOP ecall");
    check(paths[p](1, 0x11dc, 0) == 0x11dc, "post-ecall continuation advanced twice");
    check(paths[p](1, 0x11d8, 0) == 0x11d8, "timer-preempted ecall instruction skipped");
    check(paths[p](1, 0x1236, 0) == 0x1236, "compressed-instruction resume PC changed");
    check(paths[p](0, 0, 1) == 0x90000000, "fresh entry PC changed");
  }
  check(host_resume(0, 0x11d8) == 0x11dc, "host OCALL return PC");
  check(host_resume(1, 0x11dc) == 0x11dc, "host post-ecall return PC");
  check(host_resume(1, 0x1236) == 0x1236, "host interrupted exact PC");
  for (int advance = 0; advance < 2; ++advance) {
    check(rollback_0(advance) == 0x11d8, "active-switch failure skips next instruction");
    check(rollback_1(advance) == 0x11d8, "PMP install failure skips next instruction");
  }
  /* Repeated OCALL ACK, peer restore, timer save and HOST restore transitions. */
  for (int i = 0; i < 1000; ++i) {
    uintptr_t pc = paths[i % 2](0, 0x11d8, 0);
    check(host_resume(1, pc) == 0x11dc, "mixed resume path loses PC origin");
  }
  puts("SM OCALL/peer/timer/HOST resume PC and failed-switch regression PASS");
}
'''


def main():
    root = pathlib.Path(__file__).resolve().parents[3]
    source = (root / "sm/src/enclave.c").read_text(encoding="utf-8")
    ecall = function(source, "group_scheduler_direct_switch_from_ecall")
    timer = function(source, "group_scheduler_timer_switch")
    host = function(source, "context_switch_to_enclave")
    helper = ""
    if "static void group_scheduler_adjust_resume_pc(" in source:
        helper = function(source, "group_scheduler_adjust_resume_pc")
    program = (PRELUDE + helper + resume_wrapper(ecall, "ecall_resume") +
               resume_wrapper(timer, "timer_resume") + host_wrapper(host) +
               rollback_wrappers(ecall) + MAIN)
    with tempfile.TemporaryDirectory(prefix="keystone-sm-resume-") as tmp:
        cfile = pathlib.Path(tmp) / "test.c"
        binary = pathlib.Path(tmp) / "test"
        cfile.write_text(program, encoding="ascii")
        subprocess.run([os.environ.get("CC", "gcc"), "-std=c11", "-O2",
                        "-Wall", "-Wextra", "-Werror", str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
