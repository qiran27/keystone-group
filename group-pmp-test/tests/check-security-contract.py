#!/usr/bin/env python3
"""Static integration fences; these are NOT hardware isolation results."""
from pathlib import Path
import re

root = Path(__file__).resolve().parent.parent
cmake = (root / "CMakeLists.txt").read_text()
runner = (root / "host/group-pmp-test-runner.cpp").read_text()
driver = (root.parent.parent / "linux-keystone-driver/keystone-ioctl.c").read_text()
deploy = (root / "rebuild-and-test.sh").read_text()
wrapper = (root / "run-security-experiments.sh").read_text()
runtime = (root.parent.parent / "runtime/call/sbi.c").read_text()
query = re.search(r"sbi_yxstm_query_slot\(.*?\n\}", runtime, re.S).group()
assert "SBI_CALL_DETAIL" in query
assert "keystone-security-slot-error-detail-v1" in query
links = re.findall(r"target_link_libraries\((.*?)\)", cmake, re.S)
for link in links:
    if "group-pmp-security-aead-lib" in link:
        assert link.split()[0] in ("group-pmp-security-aead", "group-pmp-sqlite-worker", "group-pmp-kv-worker"), link
assert 'MBEDTLS_CONFIG_FILE="aead-config.h"' in cmake
assert 'security_fixture=aes-128-gcm,chacha20-poly1305' in runner
assert '"performance_cipher=" << selected_benchmark_cipher_name()' in runner
assert 'export GROUP_PMP_BENCH_CIPHER=aes-ecb-128' in wrapper
assert 'refusing historical destructive EPM ioctl' in runner
for name in ("keystone_test_os_access_epm_run_enclave", "keystone_test_os_access_epm_resume_enclave"):
    body = re.search(r"int " + name + r"\(.*?\n\}", driver, re.S).group()
    assert "keystone_test_os_access_region" in body
    assert not re.search(r"\b(memcpy|memset)\s*\(", body)
assert 'module_param(security_nofault_epm, bool, 0444)' in driver
assert 'copy_from_kernel_nofault(&read_value' in driver
assert 'keystone_put_kernel_u8_nofault(pointer' in driver
assert 'cp -R "$SCRIPT_DIR/security/." "$target_dir/security/"' in deploy
assert 'group-pmp-security-scan" "$deploy_dir/"' in deploy
assert 'GROUP_PMP_TEST_MODE=lease-recover timeout' in wrapper
assert "SKIP_DRIVER_CAPABILITY" in wrapper
assert "SKIP_NO_PRODUCTION_AEAD" in wrapper
extended = (root / 'run-security-plaintext.sh').read_text()
assert 'GROUP_PMP_SECURITY_CAPTURE_WORKERS=$n' in extended
assert "second argument must be 4" in wrapper
assert "security_worker_set=1,4" in runner and 'run-security-plaintext.sh' in wrapper
assert 'sqlite_worker_count_selected(workers) && sqlite_workload_selected(workload)' in runner
assert '!security_scan_nonce() || max_workers != 4 || repetitions != 1' in runner
init = re.search(r"init_instance\(.*?\nbool\nfinalize_instance", runner, re.S).group()
finalize = re.search(r"finalize_instance\(.*?\nbool\nrun_instance", runner, re.S).group()
assert 'security_region("add"' not in init
assert finalize.index('instance.enclave->finalize()') < finalize.index('security_region("add"')
security = re.search(r"bool run_security_case\(.*?\nbool\nreset_group_perf_counters", runner, re.S).group()
assert '->run(' not in security and 'run_security_guest' in security
assert 'aead ? UINT64_C(4) * 1024 * 1024' in security
assert 'run_security_authorized_control(master, worker' in security
access = (root / "eapp/group-pmp-security-access.c").read_text()
assert 'MASTER_DISPATCH_ACQUIRE' in access and 'MASTER_DISPATCH_PUBLISH' in access
assert 'acquire_mask' not in access and 'release_mask' not in access
assert 'security_fixture_version=7' in wrapper and 'security_fixture_version=7' in runner
config = (root / 'security/aead-config.h').read_text()
assert '#define MBEDTLS_BLOCK_CIPHER_C' in config
assert '#define MBEDTLS_CIPHER_C' not in config
assert 'security_gcm_memory=inline-block-cipher' in runner
leased = re.search(r"SecurityGuestEvent run_security_aead_worker\(.*?\nbool run_security_case", runner, re.S).group()
assert 'groupLeaseWorkers' in leased and 'groupWaitEvent' in leased and 'groupReleaseWorkers' in leased
assert 'device.groupRunHart(' not in leased and 'run_security_guest(' not in leased
assert 'pin_current_thread_to_cpu(kHousekeepingCpu' in leased
assert 'seconds(120)' in leased and 'event.eid != expected_eid' in leased
assert 'event.hart_id != hart' in leased and 'event.queue_overflows' in leased
assert 'event.value != SECURITY_AEAD_OCALL' not in leased
assert 'security_aead_ocall_identity_valid(event.value,' in leased
assert 'event.eid, event.value, &enclaves' in leased
identity = re.search(r"bool security_aead_ocall_identity_valid\(.*?\n\}", runner, re.S).group()
assert 'header.call_id == SECURITY_AEAD_OCALL' in identity and '!resume_token' in identity
assert 'run_security_aead_worker(enclaves, index)' in security
aead = (root / 'eapp/group-pmp-security-aead.c').read_text()
assert aead.index('exchange(&call, &reply)') < aead.index('security_aead_self_test_algorithm(algorithm)')
assert 'progress_snapshot=best-effort' in leased
assert 'SECURITY_AEAD_CONFIG_RETURNED' in aead and 'SECURITY_AEAD_KAT_STARTED' in aead
assert 'stage=ocall-resume-issued' in leased
assert 'for io in sync-no-extent async-no-extent adaptive-extent; do' in extended
assert 'GROUP_PMP_SQLITE_TOTAL_BYTES=1000000' in extended
assert 'security_capture_batch_requests=8' in extended
assert 'keystone-security-capture-milestones-v2' in extended
assert 'for rep in $(seq 1 "$repetitions")' in extended
assert 'case "$repetitions" in 1|3)' in extended
assert 'export GROUP_PMP_BENCH_CIPHER=aes-ecb-128' in extended
assert 'unsupported' in extended and 'standalone-AEAD-fixture-is-not-this-workload' in extended
assert 'Host heap/stack' not in wrapper
assert '--security-scan-info' not in wrapper
assert 'SECURITY_VERIFY_INDEPENDENT' in wrapper and 'exit 3' in wrapper
worker = (root / "eapp/group-pmp-sqlite-worker.c").read_text()
warmed = worker.index('publish_result(&result, GROUP_PMP_MIXED_STATE_WARMED)')
assert worker.index('foreign_slot_metadata_rc=') < warmed
assert worker.index('sentinel=installed-in-EPM') < warmed
assert worker.index('fflush(stdout) != 0') < warmed
assert '(config.diagnostic_flags & GROUP_PMP_SECURITY_SENTINEL_FLAG) &&\n      fflush(stdout)' in worker
assert 'expected_vfs_host_ocalls != timing.worker_ocalls' in runner
assert 'SECURITY_AEAD_OCALL < MAX_EDGE_CALL' in runner
io = (root / "host/sqlite-extent-io.cpp").read_text()
assert 'security_io_ring_region' not in io
assert 'SecurityCipherRegion(group.read_buffer.get(), span)' in io
scanner = (root / "security/security-scan.cpp").read_text()
assert 'proc + "/maps"' not in scanner and 'io-uring-snapshot-' not in scanner
assert 'registered-ciphertext-only' in scanner and 'host-ciphertext-buffer' in scanner
assert '!total.strict_errors' in scanner and 'total.positive_hits' in scanner
assert 'security_checkpoint_clock().workload_now()' in runner
assert 'now >= overall_deadline || event_stalled' in runner
assert 'progress_now - last_event_progress' in runner
hooks = (root / 'security/security-host-hooks.hpp').read_text()
assert 'std::chrono::seconds(120)' in hooks
assert 'security_checkpoint_clock().end(now)' in hooks
assert 'security_checkpoint_watchdog=2' in extended
assert 'security_capture_lifecycle=2' in extended
print("Security integration fences PASS: standalone AEAD, guarded nofault ioctl, staging and explicit skips")
