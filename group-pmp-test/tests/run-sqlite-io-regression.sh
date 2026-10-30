#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
sdk=$(CDPATH= cd -- "$root/../.." && pwd)/sdk/include
schema=$(sed -n '/kSqliteCsvSchemaVersion = UINT64_C(/s/.*UINT64_C(\([0-9][0-9]*\)).*/\1/p' "$root/host/group-pmp-test-runner.cpp")
policy=$(sed -n '/kGroupPmpSqliteExtentIoPolicyVersion = UINT64_C(/s/.*UINT64_C(\([0-9][0-9]*\)).*/\1/p' "$root/host/sqlite-extent-io.hpp")
script_schema=$(sed -n 's/^sqlite_csv_schema_version=\([0-9][0-9]*\).*/\1/p' "$root/run-p10-mixed-scaling.sh")
script_policy=$(sed -n 's/^sqlite_extent_policy_version=\([0-9][0-9]*\).*/\1/p' "$root/run-p10-mixed-scaling.sh")
[ -n "$schema" ] && [ "$schema" = "$script_schema" ]
[ -n "$policy" ] && [ "$policy" = "$script_policy" ]
grep -Fq "keystone-sqlite-csv-schema-v$schema\"" "$root/host/group-pmp-test-runner.cpp"
echo "Script/runner schema=$schema and I/O policy=$policy agree"
python3 "$here/check-sqlite-artifact-contract.py"
python3 "$here/check-sqlite-rebuild-contract.py"
python3 "$here/check-sqlite-cluster-wrapper.py"
python3 "$here/check-sqlite-calibration.py"
for file in host/sqlite-gantt-trace.hpp host/sqlite-gantt-trace.cpp \
            rebuild-and-test.sh run-p10-mixed-scaling.sh; do
  grep -Fq 'keystone-sqlite-gantt-trace-v4' "$root/$file"
done
if grep -q 'SQLITE_GANTT_\(SM_WAKE\|ENCLAVE_RESUMED\)' "$root/host/group-pmp-test-runner.cpp"; then
  echo 'Host must not fabricate SM/enclave execution timestamps' >&2
  exit 1
fi
python3 "$here/check-rebuild-source-sync.py"
python3 "$here/check-hsm-mailbox-handoff.py"
python3 "$here/check-hsm-idle-wakeup.py"
python3 "$here/check-host-ipi-context.py"
python3 "$here/check-sm-resume-pc.py"
python3 "$here/check-sqlite-small-samples.py"
sh "$here/check-sqlite-size-sweep.sh"
python3 "$here/check-sqlite-neighbor-audit.py"
python3 "$here/check-sqlite-neighbor-wrapper.py"
build=$(mktemp -d /tmp/keystone-sqlite-io-tests.XXXXXX)
trap 'rm -f "$build/store-test" "$build/host-test" "$build/csv-test" "$build/pipeline-test" "$build/intent-test" "$build/feedback-test" "$build/locality-test" "$build/sqlite3.o" "$build/merge.profile" "$build/merge.profile.tmp" "$build"/aead-*.o "$build/benchmark-aead.a"; rmdir "$build"' EXIT HUP INT TERM
cc=${CC:-gcc}
cxx=${CXX:-g++}
"$cxx" -std=c++11 -O2 -Wall -Wextra -Werror \
  "$here/online-cluster-feedback-test.cpp" -o "$build/feedback-test"
"$build/feedback-test"
"$cc" -std=gnu11 -O3 -Wall -Wextra -Werror -fsyntax-only \
  -I"$sdk" -I"$sdk/app" -I"$root/eapp" -I"$root/sqlite-bench-master" \
  "$root/sqlite-bench-master/keystone_enclave_store.c" \
  "$root/eapp/group-pmp-sqlite-worker.c"
echo 'Production store/worker C syntax PASS (native compiler, not a RISC-V link)'
# Poison same-name headers ahead of the SDK to catch accidental ABI shadowing.
"$cc" -std=gnu11 -O2 -Wall -Wextra -Werror \
  -I"$here/include-shadow" -I"$sdk" -I"$root/eapp" \
  "$here/sqlite-store-pipeline-test.c" "$root/eapp/group-pmp-crypto.c" \
  "$root/eapp/aes_core.c" $(sh "$here/build-benchmark-aead.sh" "$build") -o "$build/store-test"
"$build/store-test"
"$cc" -O2 -w -DSQLITE_THREADSAFE=1 -c \
  "$root/sqlite-bench-master/sqlite3.c" -o "$build/sqlite3.o"
"$cxx" -std=c++11 -O2 -Wall -Wextra -Werror -pthread \
  -I"$here/include-shadow" -I"$root/eapp" \
  "$here/sqlite-extent-service-test.cpp" "$root/host/sqlite-gantt-trace.cpp" \
  "$root/host/sqlite-io-range-trace.cpp" "$build/sqlite3.o" -ldl \
  -o "$build/host-test"
"$build/host-test"
probe_status=0
"$build/host-test" --probe || probe_status=$?
if [ "$probe_status" -eq 77 ]; then
  echo 'I/O probe SKIP: this kernel cannot provide registered io_uring'
elif [ "$probe_status" -ne 0 ]; then
  exit "$probe_status"
else
  GROUP_PMP_SQLITE_CACHE_MODE=cold "$build/host-test" --calibrate "$build/merge.profile"
fi
"$cxx" -std=c++11 -O2 -Wall -Wextra -Werror -pthread \
  "$here/sqlite-locality-planner-test.cpp" "$root/host/sqlite-gantt-trace.cpp" \
  "$root/host/sqlite-io-range-trace.cpp" "$build/sqlite3.o" -ldl -o "$build/locality-test"
"$build/locality-test"
"$cxx" -std=c++11 -O2 -Wall -Wextra -Werror -pthread \
  "$here/sqlite-persistent-pipeline-test.cpp" "$root/host/sqlite-gantt-trace.cpp" \
  "$root/host/sqlite-io-range-trace.cpp" "$build/sqlite3.o" -ldl \
  -o "$build/pipeline-test"
"$build/pipeline-test"
"$cxx" -std=c++11 -O2 -Wall -Wextra -Werror -pthread \
  "$here/sqlite-intent-plan-test.cpp" "$root/host/sqlite-gantt-trace.cpp" \
  "$root/host/sqlite-io-range-trace.cpp" "$build/sqlite3.o" -ldl \
  -o "$build/intent-test"
"$build/intent-test"
"$cxx" -std=c++11 -O1 -ffunction-sections -fdata-sections \
  -Wl,--gc-sections -pthread -I"$here/include-shadow" -I"$sdk" -I"$root/eapp" \
  "$here/sqlite-csv-test.cpp" "$root/host/sqlite-extent-io.cpp" \
  "$root/host/sqlite-gantt-trace.cpp" "$root/host/sqlite-io-range-trace.cpp" \
  "$build/sqlite3.o" -ldl -o "$build/csv-test"
"$build/csv-test"
sh -n "$root/run-p10-mixed-scaling.sh"
sh -n "$root/run-sqlite-neighbor-diagnostic.sh"
bash -n "$root/rebuild-and-test.sh"
echo 'SQLite I/O regression and shell syntax PASS'
