#!/bin/sh
set -eu
root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -r "$work"' EXIT HUP INT TERM
mkdir -p "$work/app" "$work/data"
cp "$root/run-security-plaintext.sh" "$work/app/"
cat > "$work/app/group-pmp-test-runner" <<'EOF'
#!/bin/sh
case "${1:-}" in
  --artifact-info) echo artifact=synthetic-wrapper-fixture ;;
  --security-crypto-info) echo 'security_capture_version=1 scan_workload_ciphers=aes-128-ecb security_checkpoint_watchdog=2 security_capture_input_bytes=1000000 security_capture_batch_requests=8 security_capture_ring_accounting=2' ;;
esac
exit 0
EOF
cat > "$work/app/group-pmp-security-capture" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = --capture-info ]; then echo 'security_capture_version=1 security_capture_preflight=1 security_capture_checkpoint_ids=1 security_capture_lifecycle=2 security_capture_compact=1 security_capture_process_stop=1'; exit 0; fi
if [ "${1:-}" = --preflight ]; then
  echo 'synthetic observer preflight; no board coverage claim'
  exit "${CAPTURE_FIXTURE_PREFLIGHT_RC:-0}"
fi
[ "$GROUP_PMP_SQLITE_TOTAL_BYTES" = 1000000 ] && [ "$GROUP_PMP_SQLITE_REPETITIONS" = 1 ]
[ "$GROUP_PMP_MIXED_WARMUP_TIMEOUT_MS" = 1800000 ]
case "$GROUP_PMP_SECURITY_CAPTURE_WORKERS:$GROUP_PMP_SECURITY_CAPTURE_WORKLOAD" in
  1:readrandom|4:readrandom|1:fillrandom|4:fillrandom) ;; *) exit 9 ;;
esac
printf '%s %s %s %s\n' "$GROUP_PMP_SECURITY_CAPTURE_WORKERS" "$GROUP_PMP_SECURITY_CAPTURE_WORKLOAD" "$GROUP_PMP_SQLITE_IO_MODE" "${SECURITY_CAPTURE_POSITIVE:-0}" >> "$CAPTURE_FIXTURE_CALLS"
echo 'mock-ciphertext-not-measured' > "$3/data.bin"
echo 'Fixture only: capture has not been verified' > "$2/fixture.txt"
EOF
cat > "$work/app/prepare-3w1hm-isolation.sh" <<'EOF'
#!/bin/sh
exit 0
EOF
printf '%s\n' keystone-security-capture-milestones-v2 > "$work/app/group-pmp-sqlite-worker.eapp_riscv"
touch "$work/app/eyrie-rt" "$work/app/loader.bin"
chmod +x "$work/app/group-pmp-test-runner" "$work/app/group-pmp-security-capture" "$work/app/prepare-3w1hm-isolation.sh"
export GROUP_PMP_RUN_LOCK_DIR=$work/lock SECURITY_SCAN_STORAGE_DIR=$work/data CAPTURE_FIXTURE_CALLS=$work/calls
rc=0
CAPTURE_FIXTURE_PREFLIGHT_RC=2 sh "$work/app/run-security-plaintext.sh" "$work/missing-observer" > "$work/missing.log" 2>&1 || rc=$?
[ "$rc" -eq 2 ] && [ ! -e "$work/calls" ] && [ ! -e "$work/lock" ]
[ ! -e "$work/missing-observer/execution-matrix.csv" ]
grep -q 'prerequisites failed; no workload launched' "$work/missing.log"
sh "$work/app/run-security-plaintext.sh" "$work/results" 3 > "$work/run.log"
[ "$(wc -l < "$work/calls")" -eq 48 ]
[ "$(find "$work/results" -name configuration.json | wc -l)" -eq 48 ]
awk -F, 'NR>1 {n++;if($8!="not-executed")exit 1} END{if(n!=108)exit 1}' "$work/results/planned-combinations.csv"
awk -F, 'NR>1 {n++;if($8=="unsupported")u++;if($8=="captured-unverified")c++;if($9!=""||$10!=""||$11!="")exit 1} END{if(n!=120||u!=72||c!=48)exit 1}' "$work/results/execution-matrix.csv"
python3 - "$work/results" <<'PY'
import json,sys
from pathlib import Path
for path in Path(sys.argv[1]).glob('*/configuration.json'):
    config=json.loads(path.read_text())
    assert config['cache_mode']=='cold' and config['random_seed']==51
    assert config['total_bytes']==1000000 and config['effective_total_bytes']==999840
    assert config['security_batch_requests']==8
    assert config['host_snapshot_protocol']==1
    assert config['environment_evidence']=='../environment.txt'
    assert config['build_evidence']=='../artifacts.sha256'
PY
[ "$(find "$work/data" -mindepth 1 | wc -l)" -eq 0 ]
[ ! -e "$work/lock" ]
if sh "$work/app/run-security-plaintext.sh" "$work/results" >/dev/null 2>&1; then exit 1; fi
CAPTURE_FIXTURE_CALLS="$work/single-calls" sh "$work/app/run-security-plaintext.sh" "$work/single" > "$work/single.log"
[ "$(wc -l < "$work/single-calls")" -eq 24 ]
awk -F, 'NR>1 {n++;if($7!=1)exit 1} END{if(n!=36)exit 1}' "$work/single/planned-combinations.csv"
awk -F, 'NR>1 {n++;if($8=="unsupported")u++;if($8=="captured-unverified")c++;if($7>1)exit 1} END{if(n!=48||u!=24||c!=24)exit 1}' "$work/single/execution-matrix.csv"
cp "$root/run-security-experiments.sh" "$work/app/"
# Setup failure must not start the remaining fixtures.
printf '#!/bin/sh\nexit 2\n' > "$work/app/run-security-plaintext.sh"
rc=0
sh "$work/app/run-security-experiments.sh" all 4 1 "$work/public-setup-failed" > "$work/setup.log" 2>&1 || rc=$?
[ "$rc" -eq 2 ] && [ ! -e "$work/public-setup-failed/security-results.csv" ]
grep -q 'plaintext setup failed' "$work/setup.log"
# The public entry has no sweep and must not call capture success a scan PASS.
printf '#!/bin/sh\n[ "$2" = "${CAPTURE_EXPECT_REPETITIONS:-3}" ] || exit 2\nexit 0\n' > "$work/app/run-security-plaintext.sh"
rc=0
sh "$work/app/run-security-experiments.sh" scan 4 3 "$work/public" > "$work/public.log" || rc=$?
[ "$rc" -eq 3 ] && grep -q 'pending independent verification' "$work/public.log"
rc=0
CAPTURE_EXPECT_REPETITIONS=1 sh "$work/app/run-security-experiments.sh" scan 4 1 "$work/public-single" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 3 ]
rc=0
sh "$work/app/run-security-experiments.sh" scan 4 2 "$work/public" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ]
rc=0
sh "$work/app/run-security-experiments.sh" verify 4 3 "$work/results" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ]
mkdir "$work/app/security-evidence" "$work/results/plaintext-evidence"
touch "$work/results/plaintext-evidence/planned-combinations.csv"
printf 'import sys\nassert sys.argv[1].endswith("/plaintext-evidence")\n' > "$work/app/security-evidence/verify-capture.py"
SECURITY_VERIFY_INDEPENDENT=1 sh "$work/app/run-security-experiments.sh" verify 4 3 "$work/results"
echo 'Capture wrapper: one/three repetitions, observer failure before workloads, blank unverified counters and cleanup PASS (mock runner)'
