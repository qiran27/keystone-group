#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1
root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -r "$work"' EXIT HUP INT TERM
g++ -std=c++11 -O2 -Wall -Wextra -Werror -pthread "$root/tests/security-checkpoint-clock-test.cpp" -o "$work/clock-test"
"$work/clock-test"
g++ -std=c++11 -O2 -Wall -Wextra -Werror -pthread "$root/tests/security-kernel-record-test.cpp" -Wl,--wrap=ioctl -o "$work/kernel-record-test"
mkdir "$work/kernel-record"
"$work/kernel-record-test" "$work/kernel-record"
g++ -std=c++11 -O2 -Wall -Wextra -Werror -pthread "$root/tests/security-process-stop-test.cpp" -o "$work/process-stop-test"
timeout 20 "$work/process-stop-test"
g++ -std=c++11 -O2 -Wall -Wextra -Werror -pthread "$root/security/security-capture.cpp" -o "$work/capture"
"$work/capture" --capture-info | grep -q 'security_capture_preflight=1'
"$work/capture" --capture-info | grep -q 'security_capture_checkpoint_ids=1'
"$work/capture" --capture-info | grep -q 'security_capture_lifecycle=2'
"$work/capture" --capture-info | grep -q 'security_capture_compact=1'
"$work/capture" --capture-info | grep -q 'security_capture_process_stop=1'
if [ ! -e /dev/keystone-evidence ]; then
  rc=0
  "$work/capture" --preflight > "$work/preflight.log" 2>&1 || rc=$?
  [ "$rc" -eq 2 ] && grep -q 'observer unavailable' "$work/preflight.log"
fi
g++ -std=c++11 -O2 -Wall -Wextra -Werror -pthread "$root/tests/security-scan-fixture.cpp" -o "$work/fixture"
mkdir -p "$work/healthy/data" "$work/leak/data" "$work/cleanup/data" "$work/compact/data"
"$work/capture" 993381 "$work/healthy" "$work/healthy/data" -- "$work/fixture" "$work/healthy/data/cipher.bin" healthy > "$work/healthy.log"
"$work/capture" 993382 "$work/leak" "$work/leak/data" -- "$work/fixture" "$work/leak/data/cipher.bin" unregistered-leak > "$work/leak.log"
"$work/capture" 993383 "$work/cleanup" "$work/cleanup/data" -- "$work/fixture" "$work/cleanup/data/cipher.bin" final-cleanup > "$work/cleanup.log"
grep -q 'periodic sampling stopped before ACK' "$work/cleanup.log"
GROUP_PMP_SQLITE_TOTAL_BYTES=1000000 "$work/capture" 993384 "$work/compact" "$work/compact/data" -- "$work/fixture" "$work/compact/data/cipher.bin" compact-runtime > "$work/compact.log"
# Native machine has no matching board observer: capture is never called PASS.
grep -q 'hits=unverified' "$work/healthy.log"
grep -q 'module-interface-unavailable' "$work/healthy/gaps.csv"
python3 - "$root" "$work" <<'PY'
import csv,importlib.util,json,sys
from pathlib import Path
root,work=map(Path,sys.argv[1:])
with (work/'cleanup/phases.csv').open() as f:
    phases=list(csv.DictReader(f))
final=[int(p['snapshot']) for p in phases if p['phase']=='after-cleanup' and p['kind']=='checkpoint']
assert len(final)==1
assert not any(p['kind']=='periodic' and int(p['snapshot'])>final[0] for p in phases)
assert (work/'cleanup/regions.log.ack').read_text().strip()=='2'
with (work/'compact/phases.csv').open() as f:
    phases=list(csv.DictReader(f))
assert sum(p['kind']=='running-sample' for p in phases)==1
with (work/'compact/reads.csv').open() as f:
    compact_reads=list(csv.DictReader(f))
assert any(r['status']=='not-applicable' and r['reason']=='unbacked-PROT_NONE-reservation'
           and int(r['length'])>=1044480 for r in compact_reads)
assert any('---p' in r['object'] and r['status']=='covered' and int(r['bytes_read'])==4096
           for r in compact_reads)
with (work/'compact/process-stops.csv').open() as f:
    stops={r['snapshot']:r for r in csv.DictReader(f)}
for r in compact_reads:
    if r['region'] not in ('host-process','kernel-io-uring','kernel-vma'):continue
    stop=stops[r['snapshot']]
    assert stop['status']=='resumed'
    assert int(stop['requested_ns'])<=int(stop['stopped_ns'])<=int(r['time_ns'])<=int(stop['resume_ns'])
spec=importlib.util.spec_from_file_location('verifier',root/'security/verify-capture.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
for name,nonce in [('healthy',993381),('leak',993382)]:
    d=work/name
    (d/'configuration.json').write_text(json.dumps(dict(run_id=name,positive=False,nonce=str(nonce),
        workload='readrandom',workers=1,positive_run='missing-control',swap_enabled=False,dump_enabled=False)))
assert v.verify(work/'healthy')['status']=='COVERAGE_INCOMPLETE'
assert v.verify(work/'leak')['status']=='PLAINTEXT_HIT'
PY
python3 "$root/tests/check-security-capture.py"
sh "$root/tests/check-security-capture-wrapper.sh"
sh -n "$root/run-security-plaintext.sh"
sh -n "$root/run-security-experiments.sh"
sh -n "$root/security/build-evidence-module.sh"
bash -n "$root/rebuild-and-test.sh"
echo 'Extended native collection: unregistered leak detected; missing module and absent controls never PASS'
