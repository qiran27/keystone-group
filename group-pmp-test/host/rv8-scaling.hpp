/* Included inside the runner namespace to reuse the real group/lease path. */

static double rv8_median(std::vector<double> values) {
  std::sort(values.begin(), values.end());
  const size_t n = values.size();
  return n % 2 ? values[n/2] : (values[n/2-1] + values[n/2]) / 2;
}

bool run_rv8_scaling_phase(const char* master, const char* runtime, const char* loader) {
  static const volatile char marker[] __attribute__((used)) = RV8_BENCH_MARKER;
  static const volatile char ocall_init_marker[] __attribute__((used)) =
      "keystone-rv8-control-only-v2";
  static const char* names[] = {"bigint", "miniz", "norx", "aes", "qsort", "sha-512", "dhrystone", "primes"};
  const char* name = std::getenv("GROUP_PMP_RV8_KERNEL");
  const char* output = std::getenv("GROUP_PMP_RV8_CSV");
  const char* raw_output = std::getenv("GROUP_PMP_RV8_SAMPLES_CSV");
  const uint64_t workers_max = env_u64("GROUP_PMP_RV8_MAX_WORKERS", 15, 1, 15);
  const uint64_t repeats = env_u64("GROUP_PMP_RV8_REPETITIONS", 5, 1, 20);
  const uint64_t requested = env_u64("GROUP_PMP_SQLITE_TOTAL_BYTES", 60000000, 1, UINT64_MAX);
  uint64_t profile = 0;
  for (uint64_t i = 0; i < 8; ++i) if (name && std::strcmp(name, names[i]) == 0) profile = i + 1;
  if (marker[0] != 'k' || ocall_init_marker[0] != 'k' ||
      !profile || !output || !raw_output ||
      std::strcmp(output, raw_output) == 0 ||
      sqlite_benchmark_io_mode() == SQLITE_BENCHMARK_IO_ADAPTIVE_EXTENT) {
    std::cerr << "[rv8] requires a valid kernel, distinct CSV paths and Sync/Async mode" << std::endl;
    return false;
  }
  if (requested < 60000000 || requested > 500000000) {
    std::cerr << "[rv8] work size must be 60..500 MB" << std::endl;
    return false;
  }
  // Only the master's two measurement-control markers use an OCALL.
  if (register_call(1, group_pmp_ocall_ack) != 0) {
    std::cerr << "[rv8] failed to register control ACK handler"
              << std::endl;
    return false;
  }
  const std::string worker = "group-pmp-rv8-" + std::string(name) + "-worker.eapp_riscv";
  std::ofstream raw(raw_output), summary(output);
  if (!raw || !summary) return false;
  raw << "version,kernel,mode,workers,sample,total_bytes,seconds,mb_per_sec,kernel_cpu_seconds,kernel_elapsed_seconds_sum,kernel_mb_per_cpu_second,transport_aes_cpu_seconds,logical_requests,host_data_operations,doorbells,completion_waits,kernel_blocks,validated\n";
  summary << "version,kernel,mode,workers,sample_count,total_bytes,seconds_median,seconds_min,seconds_max,seconds_p95,mb_per_sec_median,mb_per_sec_min,mb_per_sec_max,kernel_cpu_seconds_median,kernel_mb_per_cpu_second_median,transport_aes_cpu_seconds_median,logical_requests_median,host_data_operations_median,doorbells_median,completion_waits_median,kernel_blocks_median,validated\n";
  raw << std::fixed << std::setprecision(9); summary << std::fixed << std::setprecision(9);
  std::vector<std::pair<uint64_t, uint64_t>> order;
  std::vector<std::vector<MixedRunMetrics>> samples(workers_max + 1);
  for (uint64_t r = 0; r < repeats; ++r)
    for (uint64_t n = 1; n <= workers_max; ++n) order.emplace_back(n, r + 1);
  std::mt19937_64 random(UINT64_C(557103871172));
  std::shuffle(order.begin(), order.end(), random);
  const double hz = riscv_timebase_hz();
  if (!hz) return false;
  std::cout << "[rv8] kernel=" << name << " mode=" << sqlite_benchmark_io_mode_name()
            << " workers=1.." << workers_max << " repetitions=" << repeats
            << " storage=none total=fixed kernel_block=64KiB compute=private-EPM"
            << " timing=master-first-dispatch-to-final-aggregate includes=kernel+validation+task-protocol"
            << " kernel_cpu_clock=SM-exec-clock data_utm=0 transport_AES=0 mode_semantics=identical-compute"
            << " MB=work-scale-for-bigint-dhrystone-primes;input-bytes-for-other-kernels" << std::endl;
  for (size_t i = 0; i < order.size(); ++i) {
    MixedWorkload workload;
    MixedRunMetrics metric;
    const uint64_t n = order[i].first;
    std::cout << "[rv8-run] start=" << i+1 << "/" << order.size() << " kernel=" << name
              << " workers=" << n << " sample=" << order[i].second << "/" << repeats << std::endl;
    if (stop_requested || !build_mixed_workload(n, GROUP_PMP_MIXED_OCALL_PER_TASK,
          &workload, GROUP_PMP_SQLITE_FILLSEQ)) return false;
    workload.rv8_profile = profile;
    const bool ok = run_mixed_scaling_case(master, worker.c_str(), runtime, loader,
                                         workload, nullptr, &metric);
    if (!ok || metric.rv8_bytes != workload.total_bytes || metric.seconds <= 0 ||
        !metric.rv8_cpu_ticks || metric.worker_aes_time_ticks ||
        metric.sqlite_logical_request_count || metric.sqlite_physical_request_count ||
        metric.vfs_ring_doorbell_count || metric.vfs_wait_count) return false;
    auto& collected = samples[n];
    if (!validate_mixed_sample(metric, collected.empty() ? metric : collected[0],
                               collected.size(), &std::cerr)) return false;
    collected.push_back(metric);
    const double cpu = metric.rv8_cpu_ticks / hz;
    raw << "2," << name << ',' << sqlite_benchmark_io_mode_name() << ',' << n << ','
        << order[i].second << ',' << metric.total_bytes << ',' << metric.seconds << ','
        << metric.mb_per_sec << ',' << cpu << ',' << metric.rv8_elapsed_ticks / hz << ','
        << metric.total_bytes / 1e6 / cpu << ',' << metric.worker_aes_time_ticks / hz << ','
        << metric.sqlite_logical_request_count << ',' << metric.sqlite_physical_request_count << ','
        << metric.vfs_ring_doorbell_count << ',' << metric.vfs_wait_count << ','
        << metric.rv8_blocks << ",1\n";
    raw.flush();
    if (!raw) return false;
    std::cout << "[rv8-run] complete=" << i+1 << "/" << order.size()
              << " seconds=" << metric.seconds << " MB/s=" << metric.mb_per_sec
              << " kernel_MB/s/CPU=" << metric.total_bytes / 1e6 / cpu << std::endl;
  }
  for (uint64_t n = 1; n <= workers_max; ++n) {
    std::vector<double> seconds, throughput, cpu, kernel_rate, aes, logical, host, bells, waits, blocks;
    for (const auto& m : samples[n]) {
      seconds.push_back(m.seconds); throughput.push_back(m.mb_per_sec);
      cpu.push_back(m.rv8_cpu_ticks / hz); kernel_rate.push_back(m.total_bytes / 1e6 / cpu.back());
      aes.push_back(m.worker_aes_time_ticks / hz); logical.push_back(m.sqlite_logical_request_count);
      host.push_back(m.sqlite_physical_request_count); bells.push_back(m.vfs_ring_doorbell_count);
      waits.push_back(m.vfs_wait_count); blocks.push_back(m.rv8_blocks);
    }
    if (seconds.size() != repeats) return false;
    summary << "2," << name << ',' << sqlite_benchmark_io_mode_name() << ',' << n << ','
      << repeats << ',' << samples[n][0].total_bytes << ',' << rv8_median(seconds) << ','
      << *std::min_element(seconds.begin(), seconds.end()) << ','
      << *std::max_element(seconds.begin(), seconds.end()) << ',' << nearest_rank_percentile(seconds, 95) << ','
      << rv8_median(throughput) << ',' << *std::min_element(throughput.begin(), throughput.end()) << ','
      << *std::max_element(throughput.begin(), throughput.end()) << ',' << rv8_median(cpu) << ','
      << rv8_median(kernel_rate) << ',' << rv8_median(aes) << ',' << rv8_median(logical) << ','
      << rv8_median(host) << ',' << rv8_median(bells) << ',' << rv8_median(waits) << ','
      << rv8_median(blocks) << ",1\n";
  }
  raw.close(); summary.close();
  return !raw.fail() && !summary.fail();
}
