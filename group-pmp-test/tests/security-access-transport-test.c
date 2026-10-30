#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include "syscall.h"
#include "../security/security-sentinel.h"

static uint8_t* memory;
static struct group_pmp_security_probe* evidence;
static unsigned commands, fail_stage;
static uintptr_t mock_syscall(uintptr_t number, const void* input, size_t size);
#undef SYSCALL_2
#define SYSCALL_2(number, input, size) mock_syscall(number, (const void*)(uintptr_t)(input), size)
#include "group-pmp-common.h"
#define main security_access_fixture_main
#include "../eapp/group-pmp-security-access.c"
#undef main

static uintptr_t mock_syscall(uintptr_t number, const void* input, size_t size) {
  if (number == RUNTIME_SYSCALL_GROUP_PRIVATE_REGION_INFO) {
    struct group_private_region_info* info = (void*)input;
    assert(size == sizeof(*info));
    memset(info, 0, sizeof(*info));
    info->private_va_base = (uintptr_t)memory;
    info->private_size = 4096;
  } else if (number == RUNTIME_SYSCALL_YXSTM_QUERY_LAYOUT) {
    struct keystone_yxstm_layout_info* info = (void*)input;
    assert(size == sizeof(*info));
    memset(info, 0, sizeof(*info));
    info->role = SECURITY_TARGET == 4 ? GROUP_ROLE_MASTER : GROUP_ROLE_WORKER;
    info->yxstm_va_base = (uintptr_t)memory;
    info->bank_slice_size = info->slot_size = 4096;
    info->lane_id = 0;
    info->slot_offset = 0;
  } else if (number == RUNTIME_SYSCALL_YXSTM_QUERY_SLOT) {
    struct keystone_yxstm_slot_info* info = (void*)input;
    assert(size == sizeof(*info) && info->lane_id == 0 && info->slot_id == 0);
    info->state = YXSTM_SLOT_FREE;
    info->epoch = 7;
  } else {
    struct keystone_yxstm_slot_command* cmd = (void*)input;
    assert(number == RUNTIME_SYSCALL_YXSTM_SLOT_COMMAND && size == sizeof(*cmd));
    assert(cmd->expected_epoch == 7 && cmd->batch_id == 1 && cmd->task_id == 1 &&
           cmd->sequence == 1 && cmd->payload_size == 16);
    ++commands;
    if (commands == fail_stage) return 100007;
    if (commands == 1) {
      assert(cmd->operation == KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_ACQUIRE);
      assert(mprotect(memory + 4096, 4096, PROT_READ | PROT_WRITE) == 0);
      cmd->state = YXSTM_SLOT_DISPATCHING;
    } else {
      assert(commands == 2 && cmd->operation == KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_PUBLISH);
      assert(*(uint64_t*)(memory + 4096) == UINT64_C(0x7245636f6e74726f));
      assert(mprotect(memory + 4096, 4096, PROT_NONE) == 0);
      cmd->state = YXSTM_SLOT_READY;
    }
  }
  return 0;
}

int copy_to_shared_utm(uintptr_t offset, const void* source, size_t size) {
  assert(offset == GROUP_PMP_SECURITY_PROBE_OFFSET && size == sizeof(*evidence));
  memcpy(evidence, source, size);
  return 0;
}

static void check_case(unsigned failure) {
  memset(evidence, 0, sizeof(*evidence));
  fail_stage = failure;
  fflush(stdout);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) _exit(security_access_fixture_main());
  int status;
  assert(waitpid(child, &status, 0) == child);
  if (failure) {
    assert(WIFEXITED(status) && WEXITSTATUS(status) == (failure == 1 ? 93 : 94));
    assert(!evidence->attempted);
    return;
  }
  assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
  assert(evidence->magic == GROUP_PMP_SECURITY_PROBE_MAGIC && evidence->attempted == 1);
  assert(evidence->operation == (SECURITY_WRITE ? 2U : 1U));
  assert(evidence->permission_state == (SECURITY_TARGET == 4 ? 2U : SECURITY_TARGET == 1 ? 0U : 1U));
  assert(evidence->target == (uintptr_t)memory + (SECURITY_TARGET == 3 ? 8192 : 4096));
}

int main(void) {
  memory = mmap(NULL, 16384, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  evidence = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  assert(memory != MAP_FAILED && evidence != MAP_FAILED);
  check_case(0);
  if (SECURITY_TARGET == 4) { check_case(1); check_case(2); }
  munmap(memory, 16384);
  munmap(evidence, 4096);
  puts("Access fixture record/slot protocol PASS (mock permissions, NOT hardware PMP evidence)");
  return 0;
}
