/* Included inside the runner namespace: use the actual group/UTM/Host services. */
static double kv_median(std::vector<double> values) {
  std::sort(values.begin(), values.end());
  const size_t n = values.size();
  return n % 2 ? values[n / 2] : (values[n / 2 - 1] + values[n / 2]) / 2;
}

static std::vector<double> kv_io_metrics(const MixedRunMetrics& m) {
  return {double(m.sqlite_logical_request_count), double(m.sqlite_physical_request_count),
    double(m.sqlite_io_uring_submissions), double(m.vfs_ring_doorbell_count),
    double(m.sqlite_completion_wakeup_count), double(m.sqlite_merged_io_count),
    double(m.sqlite_useful_io_bytes), double(m.sqlite_physical_io_bytes),
    m.sqlite_collect_ns / 1e9, m.sqlite_sort_ns / 1e9, m.sqlite_cluster_ns / 1e9,
    m.sqlite_submit_ns / 1e9, m.sqlite_disk_io_ns / 1e9,
    m.sqlite_completion_wait_ns / 1e9, m.sqlite_storage_sync_ns / 1e9,
    m.sqlite_utm_copy_ns / 1e9, m.sqlite_completion_publish_ns / 1e9,
    double(m.sqlite_io_pipeline[SQLITE_PIPELINE_BUFFER_PUBLISH_P95_NS]),
    double(m.sqlite_io_pipeline[SQLITE_PIPELINE_BUFFER_ENQUEUE_PUBLISH_P95_NS]),
    m.sqlite_io_pipeline[SQLITE_PIPELINE_VECTOR_PREPARE_NS] / 1e9,
    m.sqlite_io_pipeline[SQLITE_PIPELINE_CANDIDATE_SCAN_NS] / 1e9,
    double(m.sqlite_registered_buffer_operations), double(m.sqlite_fixed_buffer_operations)};
}

bool run_kv_scaling_phase(const char* master, const char* runtime, const char* loader) {
  static const volatile char marker[] __attribute__((used)) = KV_BENCH_MARKER;
  const char* profile = std::getenv("GROUP_PMP_KV_PROFILE");
  const char* output = std::getenv("GROUP_PMP_KV_CSV");
  const char* raw_output = std::getenv("GROUP_PMP_KV_SAMPLES_CSV");
  const char* io_output = std::getenv("GROUP_PMP_KV_IO_CSV");
  const char* storage = std::getenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  const char* cache_env = std::getenv("GROUP_PMP_SQLITE_CACHE_MODE");
  const char* cache = sqlite_benchmark_cache_mode_name();
  const uint64_t max_workers = env_u64("GROUP_PMP_KV_MAX_WORKERS", 15, 1, 15);
  const uint64_t repeats = env_u64("GROUP_PMP_KV_REPETITIONS", 5, 1, 20);
  const uint64_t requested = env_u64("GROUP_PMP_SQLITE_TOTAL_BYTES", 60000000, 1, UINT64_MAX);
  uint64_t workload_id = 0;
  struct statfs filesystem;
  if (profile && !std::strcmp(profile, "put")) workload_id = GROUP_PMP_SQLITE_FILLRANDOM;
  if (profile && !std::strcmp(profile, "get")) workload_id = GROUP_PMP_SQLITE_READRANDOM;
  if (profile && !std::strcmp(profile, "update")) workload_id = GROUP_PMP_SQLITE_OVERWRITE;
  if (marker[0] != 'k' || !workload_id || !output || !raw_output || !io_output ||
      !storage || statfs(storage, &filesystem) ||
      !std::strcmp(output, raw_output) || !std::strcmp(output, io_output) ||
      !std::strcmp(raw_output, io_output) || requested < 60000000 || requested > 500000000 ||
      requested * 3 > static_cast<uint64_t>(filesystem.f_bavail) * filesystem.f_bsize ||
      (cache_env && std::strcmp(cache_env, "hot") && std::strcmp(cache_env, "cold")) ||
      std::getenv("GROUP_PMP_SECURITY_SENTINEL")) {
    std::cerr << "[secure-kv] invalid profile/output/storage; requires 60..500MB, hot/cold, 3x free capacity" << std::endl;
    return false;
  }
  const char* mode = std::getenv("GROUP_PMP_SQLITE_IO_MODE");
  if (!mode || (std::strcmp(mode, "sync-no-extent") &&
      std::strcmp(mode, "async-no-extent") && std::strcmp(mode, "adaptive-extent"))) return false;
  if (register_call(1, group_pmp_ocall_ack) ||
      register_call(GROUP_PMP_SQLITE_VFS_OCALL_ID, group_pmp_sqlite_async_vfs)) {
    std::cerr << "[secure-kv] failed to register shared OCALL handlers" << std::endl;
    return false;
  }
  std::ofstream raw(raw_output), summary(output), io(io_output);
  if (!raw || !summary || !io) return false;
  const char* metric_names[] = {"logical_requests", "host_data_operations", "submit_calls",
    "doorbells", "completion_wakeups", "merged_io_count", "useful_io_bytes", "physical_io_bytes",
    "collect_seconds", "sort_seconds", "cluster_seconds", "submit_seconds", "io_api_seconds",
    "io_completion_wait_seconds", "storage_sync_seconds", "utm_copy_seconds", "completion_publish_seconds",
    "last_cqe_to_buffer_publish_p95_ns", "buffer_enqueue_to_publish_p95_ns", "vector_prepare_seconds",
    "candidate_scan_seconds", "registered_buffer_operations", "fixed_buffer_operations"};
  const size_t metric_count = sizeof(metric_names) / sizeof(metric_names[0]);
  raw << "version,workload,io_mode,cache_mode,address_mode,worker_count,sample,total_bytes,seconds,mb_per_sec,ops_per_sec,aes_cpu_seconds";
  summary << "version,workload,io_mode,cache_mode,address_mode,worker_count,total_bytes,samples,seconds_median,seconds_min,seconds_max,seconds_p95,mb_per_sec_median,mb_per_sec_min,mb_per_sec_max,ops_per_sec_median,ops_per_sec_min,ops_per_sec_max";
  io << "version,workload,io_mode,cache_mode,address_mode,worker_count,total_bytes,samples";
  for (size_t i = 0; i < metric_count; ++i) {
    raw << ',' << metric_names[i]; io << ',' << metric_names[i] << "_median";
  }
  raw << ",validated,cipher\n"; summary << ",validated,cipher\n"; io << ",validated,cipher\n";
  raw << std::fixed << std::setprecision(9);
  summary << std::fixed << std::setprecision(9); io << std::fixed << std::setprecision(9);
  const double hz = riscv_timebase_hz();
  if (!hz) return false;
  std::vector<std::pair<uint64_t, uint64_t>> order;
  std::vector<std::vector<MixedRunMetrics>> samples(max_workers + 1);
  for (uint64_t r = 1; r <= repeats; ++r)
    for (uint64_t n = 1; n <= max_workers; ++n) order.emplace_back(n, r);
  std::mt19937_64 random(UINT64_C(557103871172));
  std::shuffle(order.begin(), order.end(), random);
  std::cout << "[secure-kv] profile=" << profile << " mode=" << mode
            << " cipher=" << selected_benchmark_cipher_name()
            << " authentication=" << (selected_benchmark_cipher() ? "per-request-AEAD" : "none")
            << " key_source=" << (selected_benchmark_cipher() ? "SM-platform-test-only" : "fixed-test-key")
            << " engine=fixed-key-space-prototype"
            << " key_bytes=8 record_header_bytes=16 record_io_bytes=4096+short-tail"
            << " index=worker-sharded-direct-address GET_validation=full-record"
            << " address_stream=locality-random-v1 cache=" << cache
            << " storage=" << storage << " timing=master-first-dispatch-to-final-aggregate"
            << " prefill=excluded includes=KV+selected-cipher+I/O+events+aggregation" << std::endl;
  sqlite_selected_io_cleanup_case(0, workload_id);
  for (size_t i = 0; i < order.size(); ++i) {
    const uint64_t n = order[i].first;
    MixedWorkload workload;
    MixedRunMetrics metric;
    std::cout << "[secure-kv-run] start=" << i + 1 << '/' << order.size()
              << " profile=" << profile << " workers=" << n
              << " sample=" << order[i].second << '/' << repeats << std::endl;
    if (stop_requested || !build_mixed_workload(n, GROUP_PMP_MIXED_OCALL_PER_TASK,
                                               &workload, workload_id)) return false;
    workload.kv_enabled = true;
    const bool ok = run_mixed_scaling_case(master, "group-pmp-kv-worker.eapp_riscv",
                                          runtime, loader, workload, nullptr, &metric);
    sqlite_selected_io_cleanup_case(n, workload_id);
    if (!ok || metric.seconds <= 0 || !metric.sqlite_logical_request_count ||
        !validate_mixed_sample(metric, samples[n].empty() ? metric : samples[n][0],
                               samples[n].size(), &std::cerr)) return false;
    samples[n].push_back(metric);
    raw << "1," << profile << ',' << mode << ',' << cache << ",locality-random-v1,"
        << n << ',' << order[i].second << ',' << metric.total_bytes << ',' << metric.seconds
        << ',' << metric.mb_per_sec << ',' << metric.sqlite_logical_request_count / metric.seconds
        << ',' << metric.worker_aes_time_ticks / hz;
    const auto fields = kv_io_metrics(metric);
    for (double v : fields) raw << ',' << v;
    raw << ",1," << selected_benchmark_cipher_name() << '\n'; raw.flush();
    if (!raw) return false;
    std::cout << "[secure-kv-run] complete=" << i + 1 << '/' << order.size()
              << " seconds=" << metric.seconds << " MB/s=" << metric.mb_per_sec
              << " logical=" << metric.sqlite_logical_request_count
              << " host_ops=" << metric.sqlite_physical_request_count << std::endl;
  }
  for (uint64_t n = 1; n <= max_workers; ++n) {
    std::vector<double> seconds, throughput, ops;
    std::vector<std::vector<double>> counters(metric_count);
    for (const auto& m : samples[n]) {
      seconds.push_back(m.seconds); throughput.push_back(m.mb_per_sec);
      ops.push_back(m.sqlite_logical_request_count / m.seconds);
      const auto fields = kv_io_metrics(m);
      for (size_t j = 0; j < metric_count; ++j) counters[j].push_back(fields[j]);
    }
    if (seconds.size() != repeats) return false;
    const std::string prefix = "1," + std::string(profile) + ',' + mode + ',' + cache +
        ",locality-random-v1," + std::to_string(n) + ',' + std::to_string(samples[n][0].total_bytes) +
        ',' + std::to_string(repeats);
    summary << prefix << ',' << kv_median(seconds) << ',' << *std::min_element(seconds.begin(), seconds.end())
            << ',' << *std::max_element(seconds.begin(), seconds.end()) << ',' << nearest_rank_percentile(seconds, 95)
            << ',' << kv_median(throughput) << ',' << *std::min_element(throughput.begin(), throughput.end())
            << ',' << *std::max_element(throughput.begin(), throughput.end()) << ',' << kv_median(ops)
            << ',' << *std::min_element(ops.begin(), ops.end()) << ',' << *std::max_element(ops.begin(), ops.end()) << ",1," << selected_benchmark_cipher_name() << '\n';
    io << prefix;
    for (const auto& values : counters) io << ',' << kv_median(values);
    io << ",1," << selected_benchmark_cipher_name() << '\n';
  }
  raw.close(); summary.close(); io.close();
  return !raw.fail() && !summary.fail() && !io.fail();
}
