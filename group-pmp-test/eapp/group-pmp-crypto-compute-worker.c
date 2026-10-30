#include "group-pmp-common.h"
#include "crypto-compute.h"

GROUP_PMP_DEFINE_PROTOCOL_MAILBOX(crypto_compute_clock_page);
static const volatile char marker[] __attribute__((used)) = CRYPTO_COMPUTE_MARKER;
static const volatile char startup_marker[] __attribute__((used)) = CRYPTO_COMPUTE_STARTUP_MARKER;
static uint64_t clock_generation;

static int read_clock(struct crypto_compute_stamp* out) {
  struct keystone_exec_clock_sample sample;
  const volatile struct keystone_member_exec_clock* clock =
      (const volatile struct keystone_member_exec_clock*)(uintptr_t)
      (crypto_compute_clock_page + KEYSTONE_EXEC_CLOCK_OFFSET);
  if (keystone_exec_clock_read(clock, group_pmp_rdtime, &sample) ||
      (clock_generation && clock_generation != sample.generation)) return -1;
  clock_generation = sample.generation;
  out->wall_ticks = sample.wall_ticks;
  out->cpu_ticks = sample.runtime_ticks;
  out->cycles = group_pmp_rdcycle();
  return 0;
}

int main(void) {
  struct crypto_compute_config config;
  struct crypto_compute_result result;
  if (marker[0] != 'k' || startup_marker[0] != 'k' ||
      copy_from_shared(&config, CRYPTO_COMPUTE_CONFIG_OFFSET, sizeof(config)) ||
      group_pmp_register_protocol_mailbox(crypto_compute_clock_page,
          KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK |
          KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK_ONLY)) return 1;
  const int rc = crypto_compute_run(&config, read_clock, &result);
  if (copy_to_shared_utm(CRYPTO_COMPUTE_RESULT_OFFSET, &result, sizeof(result))) return 2;
  return rc ? 3 : 0;
}
