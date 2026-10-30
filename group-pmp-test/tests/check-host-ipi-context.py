#!/usr/bin/env python3
"""Exercise real SM CSR restore/IPI helpers across a master-to-HOST return."""

from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path
import subprocess
import tempfile

here = Path(__file__).resolve().parent
project = here.parents[2]
spec = spec_from_file_location("handoff", here / "check-hsm-mailbox-handoff.py")
handoff = module_from_spec(spec)
spec.loader.exec_module(handoff)
ipi = (project / "sm/src/ipi.c").read_text()
thread = (project / "sm/src/thread.c").read_text()
process_name = "group_process_enclave_ipis"
restore_name = "group_restore_host_ipi"
process = (handoff.function(ipi, process_name) if process_name in ipi else
           "void group_process_enclave_ipis(void) { sbi_ipi_process(); }")
restore = (handoff.function(ipi, restore_name) if restore_name in ipi else
           "void group_restore_host_ipi(void) {}")
restore_csrs = handoff.function(thread, "restore_smode_csrs").replace(
    'asm volatile("sfence.vma" ::: "memory");', '(void)0;')

prelude = r'''
#include <cstdio>
#include <cstdlib>
#include <cstring>
#define MAX_HARTS 5
#define MIP_SSIP 2UL
enum { sstatus, sie, stvec, scounteren, sscratch, sepc, scause,
       sbadaddr, sip, mip = sip, satp, mhartid };
struct thread_state {
  struct { unsigned long sstatus, sie, stvec, scounteren, sscratch,
    sepc, scause, sbadaddr, sip, satp; } prev_csrs;
};
static unsigned long hart;
static unsigned long hw[MAX_HARTS][mhartid];
static unsigned long group_host_ssip_pending[MAX_HARTS];
static bool incoming_host_ipi[MAX_HARTS];
static unsigned ipi_drains;
#define csr_read(reg) ((reg) == mhartid ? hart : hw[hart][(reg)])
#define csr_set(reg, mask) (hw[hart][(reg)] |= (mask))
#define csr_clear(reg, mask) (hw[hart][(reg)] &= ~(mask))
#define csr_write(reg, val) (hw[hart][(reg)] = (val))
static void sbi_ipi_process() {
  ++ipi_drains;
  if (hart >= MAX_HARTS) return;
  if (incoming_host_ipi[hart]) csr_set(mip, MIP_SSIP);
  incoming_host_ipi[hart] = false;
}
static void require(bool value, const char* message) {
  if (!value) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
'''

tests = r'''
static void reset() {
  std::memset(hw, 0, sizeof(hw));
  std::memset(group_host_ssip_pending, 0, sizeof(group_host_ssip_pending));
  std::memset(incoming_host_ipi, 0, sizeof(incoming_host_ipi));
  hart = 1; ipi_drains = 0;
}
int main() {
  thread_state host{}, peer{};
  // CPU0 is executing master; worker notification arrives before HOST restore.
  reset();
  incoming_host_ipi[hart] = true;
  group_process_enclave_ipis();
  const bool leaked_to_runtime = (csr_read(sip) & MIP_SSIP) != 0;
  restore_smode_csrs(&host);
  group_restore_host_ipi();
  require(csr_read(sip) & MIP_SSIP,
          "worker mailbox IPI erased by restoring the master's old HOST SIP");
  require(!leaked_to_runtime, "HOST IPI must not become enclave-owned SIP");
  require(ipi_drains == 1, "IPI/coherence processing must not be skipped");
  csr_clear(sip, MIP_SSIP);
  group_restore_host_ipi();
  require(!(csr_read(sip) & MIP_SSIP), "HOST delivery must consume the latch");

  reset();
  incoming_host_ipi[hart] = true;
  group_process_enclave_ipis();
  restore_smode_csrs(&peer);
  incoming_host_ipi[hart] = true;
  group_process_enclave_ipis();
  restore_smode_csrs(&peer);
  require(!(csr_read(sip) & MIP_SSIP), "peer must not inherit a HOST IPI");
  restore_smode_csrs(&host);
  group_restore_host_ipi();
  require(csr_read(sip) & MIP_SSIP, "peer switches must preserve coalesced HOST IPI");

  for (bool host_ipi : {false, true}) {
    reset();
    csr_set(sip, MIP_SSIP); // runtime's independent software-interrupt state
    incoming_host_ipi[hart] = host_ipi;
    group_process_enclave_ipis();
    require(csr_read(sip) & MIP_SSIP, "runtime SIP must be preserved");
    restore_smode_csrs(&host);
    group_restore_host_ipi();
    require(bool(csr_read(sip) & MIP_SSIP) == host_ipi,
            "runtime SIP and HOST IPI ownership must stay separate");
  }
  reset();
  incoming_host_ipi[hart] = true;
  group_process_enclave_ipis();
  hart = 2;
  group_process_enclave_ipis(); // coherence-only IPI
  group_restore_host_ipi();
  require(!(csr_read(sip) & MIP_SSIP), "no cross-hart or coherence-only wake");
  hart = 1;
  restore_smode_csrs(&host);
  group_restore_host_ipi();
  require(csr_read(sip) & MIP_SSIP, "per-hart HOST notification was lost");

  reset();
  host.prev_csrs.sip = MIP_SSIP; // HOST IPI was pending before enclave entry
  restore_smode_csrs(&host);
  group_restore_host_ipi();
  require(csr_read(sip) & MIP_SSIP, "previously saved HOST SIP must survive");
  reset();
  incoming_host_ipi[hart] = true; // normal late IPI after HOST CSR restore
  sbi_ipi_process();
  group_restore_host_ipi();
  require(csr_read(sip) & MIP_SSIP, "normal HOST IPI must not be cleared");
  std::puts("HOST IPI context PASS: master return, peer switches, runtime isolation, coalescing, per-hart delivery");
}
'''

kernel = Path(os.environ.get("KEYSTONE_TEST_KERNEL_SOURCE", str(
    project.parent / "VisionFive2_devl/linux")))
kernel_code = ""
if (kernel / "arch/riscv/kernel/smp.c").is_file():
    smp = (kernel / "arch/riscv/kernel/smp.c").read_text()
    cpu_ops = (kernel / "arch/riscv/kernel/cpu_ops_sbi.c").read_text()
    kernel_code = r'''
#include <cerrno>
#define CONFIG_RISCV_HSM_CPU_LEASE 1
#define CSR_IP sip
#define IE_SIE MIP_SSIP
#define smp_mb__before_atomic() ((void)0)
#define smp_mb__after_atomic() ((void)0)
#define mb() ((void)0)
#define READ_ONCE(x) (x)
#define pr_warn(...) ((void)0)
#define BUG_ON(x) require(!(x), "unexpected kernel IPI type")
enum ipi_message_type { IPI_RESCHEDULE, IPI_CALL_FUNC, IPI_CPU_STOP,
  IPI_IRQ_WORK, IPI_TIMER, IPI_HSM_LEASE_EVENT, IPI_MAX };
struct { unsigned long bits, stats[IPI_MAX]; } ipi_data[MAX_HARTS];
struct cpumask { int cpu; } masks[MAX_HARTS];
struct pt_regs {};
struct riscv_ipi_ops { void (*ipi_inject)(const cpumask*); void (*ipi_clear)(); };
struct riscv_hsm_cpu_lease_ops { void (*event)(unsigned); };
static const unsigned nr_cpu_ids = MAX_HARTS - 1;
static unsigned delivered_mailboxes, callbacks, pending_mailboxes;
static bool cpu_online(unsigned cpu) { return cpu == 0; }
static unsigned smp_processor_id() { return 0; }
static unsigned raw_smp_processor_id() { return 0; }
static const cpumask* cpumask_of(int cpu) { masks[cpu].cpu = cpu; return &masks[cpu]; }
static void inject(const cpumask* mask) { incoming_host_ipi[mask->cpu + 1] = true; }
static riscv_ipi_ops kernel_ipi_ops{inject, nullptr};
static const riscv_ipi_ops* ipi_ops = &kernel_ipi_ops;
static void mailbox_event(unsigned cpu) {
  require(cpu == 0, "mailbox callback must execute on CPU0");
  ++callbacks; delivered_mailboxes += pending_mailboxes; pending_mailboxes = 0;
}
static riscv_hsm_cpu_lease_ops lease_ops{mailbox_event};
static const riscv_hsm_cpu_lease_ops* hsm_cpu_lease_ops = &lease_ops;
static void set_bit(unsigned bit, unsigned long* p) { *p |= 1UL << bit; }
static unsigned long xchg(unsigned long* p, unsigned long v) { auto old = *p; *p = v; return old; }
static pt_regs* set_irq_regs(pt_regs*) { return nullptr; }
static void irq_enter() {} static void irq_exit() {}
static void rcu_read_lock() {} static void rcu_read_unlock() {}
static void scheduler_ipi() {} static void generic_smp_call_function_interrupt() {}
static void ipi_stop() {} static void irq_work_run() {}
'''
    for source, name in ((smp, "send_ipi_single"),
                         (smp, "riscv_hsm_cpu_lease_notify"),
                         (smp, "riscv_clear_ipi"),
                         (cpu_ops, "riscv_hsm_cpu_lease_handle_event"),
                         (smp, "handle_IPI")):
        kernel_code += handoff.function(source, name) + "\n"
    kernel_code += r'''
static void kernel_bridge_test() {
  hart = 1;
  std::memset(hw, 0, sizeof(hw));
  std::memset(group_host_ssip_pending, 0, sizeof(group_host_ssip_pending));
  std::memset(ipi_data, 0, sizeof(ipi_data));
  incoming_host_ipi[hart] = false;
  delivered_mailboxes = callbacks = pending_mailboxes = 0;
  thread_state host{};
  for (unsigned lane = 0; lane < 3; ++lane) {
    ++pending_mailboxes;
    require(riscv_hsm_cpu_lease_notify(0) == 0, "kernel worker notify failed");
  }
  group_process_enclave_ipis();
  restore_smode_csrs(&host);
  group_restore_host_ipi();
  require(csr_read(sip) & MIP_SSIP, "kernel mailbox bit has no hardware notification");
  handle_IPI(nullptr);
  require(callbacks == 1 && delivered_mailboxes == 3 && !ipi_data[0].bits,
          "coalesced kernel IPI must deliver every pending lane mailbox");
  require(!(csr_read(sip) & MIP_SSIP), "kernel must consume delivered SSIP");
  std::puts("Kernel HSM IPI bridge PASS: actual notify/dispatch/callback, three coalesced lanes");
}
'''
    tests = tests.replace('  std::puts("HOST IPI context PASS:',
                          '  kernel_bridge_test();\n  std::puts("HOST IPI context PASS:')
else:
    print("Kernel IPI integration skipped: set KEYSTONE_TEST_KERNEL_SOURCE to the final kernel tree")

with tempfile.TemporaryDirectory(prefix="keystone-host-ipi-") as tmp:
    source = Path(tmp) / "test.cpp"
    binary = Path(tmp) / "test"
    source.write_text(prelude + "\n#include <initializer_list>\n" +
                      process + restore + restore_csrs + kernel_code + tests)
    subprocess.run([os.environ.get("CXX", "g++"), "-std=c++14", "-O2",
                    "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                    str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

enclave = (project / "sm/src/enclave.c").read_text()
trap = (project / "sm/src/sbi_trap_hack.c").read_text()
assert "group_process_enclave_ipis();" in trap
exit_body = handoff.function(enclave, "context_switch_to_host")
assert exit_body.index("group_scheduler_restore_thread_context_exact(host_thread") < \
       exit_body.index("group_restore_host_ipi();") < exit_body.index("switch_vector_host();")
entry_body = handoff.function(enclave, "context_switch_to_enclave")
assert "group_restore_host_ipi();" in entry_body  # failed entry restores HOST, too
