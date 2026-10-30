/* Included in the runner namespace to reuse the verified group/lease lifecycle. */
#include "../eapp/crypto-compute.h"

static int run_crypto_compute(int argc, char** argv) {
  static const volatile char marker[] __attribute__((used)) = CRYPTO_COMPUTE_MARKER;
  static const volatile char startup_marker[] __attribute__((used)) = CRYPTO_COMPUTE_STARTUP_MARKER;
  crypto_compute_config cfg = {};
  cfg.magic = CRYPTO_COMPUTE_MAGIC; cfg.version = CRYPTO_COMPUTE_VERSION;
  if (argc != 7) {
    std::cerr << "usage: --crypto-compute cipher encrypt|decrypt bytes sample samples.csv" << std::endl;
    return 2;
  }
  const std::string algorithm = argv[2], direction = argv[3];
  if (algorithm == "aes-ecb-128") cfg.algorithm = 0;
  else if (algorithm == "aes-gcm-128") cfg.algorithm = 1;
  else if (algorithm == "chacha20-poly1305") cfg.algorithm = 2;
  else return 2;
  cfg.operation = direction == "encrypt" ? 1 : direction == "decrypt" ? 2 : 0;
  if (!cfg.operation || !parse_csv_u64(argv[4], &cfg.total_bytes) ||
      !parse_csv_u64(argv[5], &cfg.sample) || !cfg.sample || cfg.sample > 20 ||
      !cfg.total_bytes || cfg.total_bytes > 500000000 || cfg.total_bytes % 16 || !argv[6][0]) return 2;
  std::signal(SIGINT, request_stop); std::signal(SIGTERM, request_stop);
  const uint64_t hz = riscv_timebase_hz();
  std::vector<EnclaveInstance> enclaves;
  Keystone::KeystoneDevice device;
  Params params;
  keystone_group_lease lease = {};
  const uint64_t flags = KEYSTONE_GROUP_LEASE_FLAG_REQUIRE_ISOLATION |
      KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE | KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE;
  uint64_t hart = UINT64_MAX;
  crypto_compute_result result = {};
  bool leased = false, ok = false;
  try {
    if (marker[0] != 'k' || startup_marker[0] != 'k' || !hz || !pin_current_thread_to_cpu(kHousekeepingCpu, "crypto-compute-host") ||
        !configure_default_group() || !device.initDevice(params)) throw std::runtime_error("group setup");
    hart = sm_hart_id_for_cpu(1);
    if (hart == UINT64_MAX) throw std::runtime_error("worker topology mapping");
    std::cout << "[crypto-compute] startup=2 worker_hart=" << hart
              << " free_bytes_per_member=" << CRYPTO_COMPUTE_FREE_BYTES << std::endl;
    // Reserve equal-sized EPM images. Member zero is an inactive group owner.
    for (unsigned i = 0; i < 2; ++i)
      add_instance(enclaves, i ? "crypto-compute-worker" : "crypto-compute-inactive-owner",
          "group-pmp-crypto-compute-worker.eapp_riscv", kDefaultGroupId, 2,
          kYxstmSize, kUtmSize, kYxstmSize / KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT,
          CRYPTO_COMPUTE_FREE_BYTES);
    if (!init_all(enclaves, "eyrie-rt", "loader.bin") || !finalize_all(enclaves))
      throw std::runtime_error("enclave initialization");
    auto& worker = *enclaves[1].enclave;
    uint8_t* utm = static_cast<uint8_t*>(worker.getOcallBuffer());
    if (!utm || worker.getOcallBufferSize() < CRYPTO_COMPUTE_RESULT_OFFSET + sizeof(result))
      throw std::runtime_error("control UTM");
    std::memcpy(utm + CRYPTO_COMPUTE_CONFIG_OFFSET, &cfg, sizeof(cfg));
    std::memset(utm + CRYPTO_COMPUTE_RESULT_OFFSET, 0, sizeof(result));
    if (!bind_and_enqueue(enclaves[1], hart) ||
        device.groupLeaseWorkers(kDefaultGroupId, flags, &lease) != Error::Success)
      throw std::runtime_error("exclusive worker lease");
    leased = true;
    const uint64_t mask = KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_EXIT) |
        KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_FAULT) |
        KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_OCALL) |
        KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_WATCHDOG) |
        KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_HEARTBEAT);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(
        env_u64("GROUP_PMP_CRYPTO_COMPUTE_TIMEOUT_SEC", 600, 10, 3600));
    bool exited = false;
    while (!stop_requested && std::chrono::steady_clock::now() < deadline) {
      keystone_group_wait_event event = {};
      const Error error = device.groupWaitEvent(kDefaultGroupId, mask, 1000, &event);
      if (error == Error::GroupEventTimeout) continue;
      if (error == Error::Success && event.event == KEYSTONE_GROUP_EVENT_EXIT)
        std::memcpy(&result, utm + CRYPTO_COMPUTE_RESULT_OFFSET, sizeof(result));
      if (error != Error::Success || event.queue_overflows || event.error ||
          event.eid != static_cast<uint64_t>(worker.getEid()) || event.hart_id != hart ||
          event.event != KEYSTONE_GROUP_EVENT_EXIT || event.value != 0) {
        std::cerr << "[crypto-compute] event=" << event.event << " eid=" << event.eid
                  << " hart=" << event.hart_id << " error=" << event.error << " retval=" << event.value
                  << " worker_error=" << result.error_code << std::endl;
        throw std::runtime_error("worker fault/unexpected event or exit status");
      }
      exited = true;
      break;
    }
    if (!exited) throw std::runtime_error("worker interrupted or timeout");
    std::memcpy(&result, utm + CRYPTO_COMPUTE_RESULT_OFFSET, sizeof(result));
    ok = result.magic == cfg.magic && result.version == cfg.version &&
        result.algorithm == cfg.algorithm && result.operation == cfg.operation &&
        result.total_bytes == cfg.total_bytes && result.sample == cfg.sample &&
        result.processed_bytes == cfg.total_bytes && result.validated == 1 &&
        result.error_code == 0 && result.cpu_ticks && result.wall_ticks >= result.cpu_ticks &&
        result.blocks == (cfg.total_bytes + CRYPTO_COMPUTE_BLOCK_BYTES - 1) / CRYPTO_COMPUTE_BLOCK_BYTES;
  } catch (const std::exception& error) {
    std::cerr << "[crypto-compute] " << error.what() << std::endl;
  }
  if (leased && device.groupReleaseWorkers(kDefaultGroupId, flags, &lease) != Error::Success) ok = false;
  destroy_instances(enclaves);
  if (!ok) { result.validated = 0; if (!result.error_code) result.error_code = 100; }
  const double wall = hz ? static_cast<double>(result.wall_ticks) / hz : 0;
  const double cpu = hz ? static_cast<double>(result.cpu_ticks) / hz : 0;
  std::ifstream existing(argv[6], std::ios::binary);
  const bool empty = !existing.good() || existing.peek() == std::ifstream::traits_type::eof();
  existing.close();
  std::ofstream csv(argv[6], std::ios::app);
  if (!csv) return 1;
  if (empty) csv << "version,cipher,operation,total_bytes,worker_count,sample,block_bytes,blocks,processed_bytes,wall_ticks,cpu_ticks,cycles,timebase_hz,wall_seconds,cpu_seconds,descheduled_seconds,wall_mb_per_sec,cpu_mb_per_sec,validated,error_code,data_io_operations,timed_ocalls,execution_environment,timing_scope\n";
  csv << std::setprecision(15) << CRYPTO_COMPUTE_VERSION << ',' << algorithm << ',' << direction << ','
      << cfg.total_bytes << ",1," << cfg.sample << ',' << CRYPTO_COMPUTE_BLOCK_BYTES << ','
      << result.blocks << ',' << result.processed_bytes << ',' << result.wall_ticks << ','
      << result.cpu_ticks << ',' << result.cycles << ',' << hz << ',' << wall << ',' << cpu << ','
      << (wall - cpu) << ',' << (wall > 0 ? result.processed_bytes / wall / 1000000 : 0) << ','
      << (cpu > 0 ? result.processed_bytes / cpu / 1000000 : 0) << ',' << result.validated << ','
      << result.error_code << ",0,0,riscv-worker-enclave,sum-of-transform-intervals\n";
  csv.close();
  std::cout << "[crypto-compute] cipher=" << algorithm << " operation=" << direction
            << " bytes=" << cfg.total_bytes << " sample=" << cfg.sample << " wall_seconds=" << wall
            << " cpu_seconds=" << cpu << " validated=" << result.validated << " result=" << (ok ? "PASS" : "FAIL") << std::endl;
  return ok && csv.good() ? 0 : 1;
}
