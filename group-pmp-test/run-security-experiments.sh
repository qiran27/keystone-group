#!/bin/sh
set -eu
# The existing evidence matrix remains ECB; new performance choices are separate.
export GROUP_PMP_BENCH_CIPHER=aes-ecb-128
cd "$(dirname "$0")"
unset GROUP_PMP_SECURITY_NONCE GROUP_PMP_SECURITY_REGIONS GROUP_PMP_SECURITY_WORKER_SET
mode=${1:-all}
workers=${2:-4}
attempts=${3:-1}
output=${4:-/myusb/security-results}
case "$mode" in all|scan|isolation|integrity|verify) ;; *) echo "mode: all|scan|isolation|integrity|verify" >&2; exit 2 ;; esac
case "$workers:$attempts" in *[!0-9:]*|:*|*:) exit 2 ;; esac
[ "$workers" -eq 4 ] || { echo 'Security scan strictly tests workers=1,4; second argument must be 4' >&2; exit 2; }
[ "$attempts" -ge 1 ] && [ "$attempts" -le 1000 ] || exit 2
if [ "$mode" = verify ]; then
  [ "${SECURITY_VERIFY_INDEPENDENT:-0}" = 1 ] || {
    echo 'Run verify on the independent trusted analysis machine and set SECURITY_VERIFY_INDEPENDENT=1' >&2; exit 2;
  }
  if [ -e "$output/plaintext-evidence/planned-combinations.csv" ]; then output=$output/plaintext-evidence; fi
  if [ -r ./security-evidence/verify-capture.py ]; then verifier=./security-evidence/verify-capture.py;
  else verifier=./security/verify-capture.py; fi
  exec python3 "$verifier" "$output"
fi
plaintext_capture_status=0
if [ "$mode" = all ] || [ "$mode" = scan ]; then
  case "$attempts" in 1|3) ;; *) echo 'Extended plaintext protocol accepts 1 or 3 repetitions' >&2; exit 2 ;; esac
  if [ "$mode" = scan ]; then
    sh ./run-security-plaintext.sh "$output" "$attempts" || exit "$?"
    echo '[security] capture pending independent verification; exit=3 is not PASS'
    exit 3
  fi
  sh ./run-security-plaintext.sh "$output/plaintext-evidence" "$attempts" || plaintext_capture_status=$?
  if [ "$plaintext_capture_status" -eq 2 ]; then
    echo '[security] plaintext setup failed; fix the recorded prerequisite error before restarting all' >&2
    exit 2
  fi
fi
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
# Refuse an occupied result directory so previous evidence is not overwritten.
[ ! -e "$output/security-results.csv" ] || { echo "Choose a new output directory" >&2; exit 2; }
lock=${GROUP_PMP_RUN_LOCK_DIR:-/tmp/keystone-group-pmp-p10.lock}
mkdir "$lock" 2>/dev/null || { echo "Another experiment owns the run lock" >&2; exit 2; }
printf '%s\n' "$$" > "$lock/pid"
cleanup() {
  GROUP_PMP_TEST_MODE=lease-recover timeout 30 ./group-pmp-test-runner \
    > "$output/lease-cleanup.log" 2>&1 || echo '[security] lease recovery failed; inspect lease-cleanup.log' >&2
  rm -f "$lock/pid"
  rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
./prepare-3w1hm-isolation.sh apply
export GROUP_PMP_SECURITY_ATTEMPTS=$attempts
nonce=$(od -An -N8 -tu8 /dev/urandom | tr -d ' \n')
case "$nonce" in ''|0|*[!0-9]*) echo "Failed to obtain run nonce" >&2; exit 2 ;; esac
export GROUP_PMP_SECURITY_AEAD_NONCE=$nonce
summary=$output/security-results.csv
printf '%s\n' 'test,precondition,actor,target,expected,actual,attempts,evidence' > "$summary"
./group-pmp-test-runner --artifact-info > "$output/artifact.log"
./group-pmp-test-runner --security-crypto-info > "$output/crypto.log"
grep -q 'security_version=1' "$output/crypto.log" || { echo 'Security runner is stale' >&2; exit 2; }
grep -q 'security_fixture_version=7' "$output/crypto.log" || {
  echo 'Rebuild/deploy runner and AEAD eapp for inline-GCM fixture v7' >&2; exit 2;
}
grep -q 'security_gcm_memory=inline-block-cipher' "$output/crypto.log" || {
  echo 'Rebuild/deploy inline-GCM security fixture' >&2; exit 2;
}
sha256sum ./group-pmp-test-runner ./group-pmp-security-*.eapp_riscv > "$output/artifacts.sha256"
dmesg > "$output/kernel-before.log" 2>/dev/null || true
failed=0
[ "$plaintext_capture_status" -eq 0 ] || failed=1
row() {
  separator=
  for field in "$@"; do
    escaped=$(printf '%s' "$field" | sed 's/"/""/g')
    printf '%s"%s"' "$separator" "$escaped" >> "$summary"
    separator=,
  done
  printf '\n' >> "$summary"
}

if [ "$mode" = all ]; then
  plaintext_actual='CAPTURED_UNVERIFIED; use offline verified-results.csv; not a PASS'
  [ "$plaintext_capture_status" -eq 0 ] || plaintext_actual='CAPTURE_FAILED_OR_INCOMPLETE; inspect plaintext-evidence; not a PASS'
  row plaintext-extended '1MB configured; 999840 effective bytes; readrandom/fillrandom; N=1,4; all three modes; ECB workload; AEAD workload unsupported' \
    'independent evidence collector and offline verifier' 'Host process, UTM, temporary buffers and referenced kernel pages' \
    'all mandatory regions/controls covered; no marker hits; valid workload' \
    "$plaintext_actual" "$attempts" "$output/plaintext-evidence/execution-matrix.csv"
fi

if [ "$mode" = all ] || [ "$mode" = isolation ]; then
  for test in authorized-control host-epm host-tsr epm-read epm-write \
              tsr-unacquired-read tsr-unacquired-write tsr-cross-read tsr-cross-write \
              tsr-revoked-read tsr-revoked-write; do
    if [ "$test" = host-epm ] &&
       ! grep -q '^Y\|^1' /sys/module/keystone_driver/parameters/security_nofault_epm 2>/dev/null; then
      row "$test" 'requires new nofault driver' Host EPM 'read/write EFAULT' \
        'SKIP_DRIVER_CAPABILITY; rebuild/reload driver' 0 "$output/crypto.log"
      continue
    fi
    for attempt in $(seq 1 "$attempts"); do
      log=$output/$test-$attempt.log
      printf '[security] isolation case=%s attempt=%s/%s log=%s\n' "$test" "$attempt" "$attempts" "$log"
      result=PASS
      GROUP_PMP_TEST_MODE=security GROUP_PMP_SECURITY_CASE=$test \
        timeout 180 ./group-pmp-test-runner > "$log" 2>&1 || result=FAIL
      if [ "$test" = authorized-control ]; then
        actor='authorized Master and Workers'; expected='task dispatch and result aggregation succeed'
      else
        actor='Host or unauthorized enclave; requester EID in log'; expected='specific probe rejected; setup failure is not success'
      fi
      row "$test" 'isolated group; explicit access probe' "$actor" "$test" \
        "$expected" "$result" 1 "$log"
      [ "$result" = PASS ] || failed=1
    done
  done
fi

if [ "$mode" = all ] || [ "$mode" = integrity ]; then
  for algorithm in gcm chacha; do
    log=$output/aead-$algorithm.log
    printf '[security] standalone AEAD=%s attempts=%s; Host CPU0 + worker lease; log=%s\n' "$algorithm" "$attempts" "$log"
    result=PASS
    GROUP_PMP_TEST_MODE=security GROUP_PMP_SECURITY_CASE=aead-$algorithm \
      timeout 180 ./group-pmp-test-runner > "$log" 2>&1 || result=FAIL
    for scenario in unaltered-control ciphertext-flip tag-flip nonce-flip aad-flip \
                    range-swap object-swap utm-before-snapshot utm-after-snapshot; do
      count=$(grep -c "scenario=$scenario .*result=PASS" "$log" || true)
      actual=$result
      [ "$count" -eq "$attempts" ] || { actual=FAIL_OR_INCOMPLETE; failed=1; }
      expected='reject; app output untouched; no valid result'
      case "$scenario" in unaltered-control|utm-after-snapshot) expected='accept verified EPM snapshot only' ;; esac
      row "aead-$algorithm-$scenario" 'security-only AEAD eapp; public test key; trusted AAD identity' \
        'Host tamper callback' "$scenario" "$expected" "$actual" "$count" "$log"
    done
    [ "$result" = PASS ] || failed=1
  done
  row 'performance-ECB-integrity' 'performance workers remain AES-128-ECB' Host \
    'existing performance storage' 'not a cryptographic authentication test' \
    'SKIP_NO_PRODUCTION_AEAD; security fixture does not certify ECB paths' 0 "$output/crypto.log"
fi
if dmesg > "$output/kernel-after.log" 2>/dev/null; then :; else
  printf '%s\n' 'kernel log unavailable; see serial capture for SM/PMP fault evidence' > "$output/kernel-after.log"
fi
printf '[security] results=%s fixture_failures=%s; negative scan is limited to recorded regions/times; no rollback claim\n' "$summary" "$failed"
[ "$failed" -eq 0 ] || exit "$failed"
if [ "$mode" = all ]; then
  echo '[security] status=PENDING_INDEPENDENT_PLAINTEXT_VERIFICATION; exit=3 is not overall PASS'
  exit 3
fi
exit "$failed"
