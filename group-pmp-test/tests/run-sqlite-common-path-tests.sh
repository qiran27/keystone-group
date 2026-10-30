#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sdk=$root/../../sdk/include
build=${SQLITE_TEST_BUILD_DIR:-$root/.test-policy44}
mkdir -p "$build"
cd "$root"
aead=$(sh tests/build-benchmark-aead.sh "$build")
if [ ! -f "$build/sqlite3.o" ]; then
  gcc -O1 -w -DSQLITE_THREADSAFE=1 -c sqlite-bench-master/sqlite3.c -o "$build/sqlite3.o"
fi
g++ -std=c++11 -O1 -Wall -Wextra -Werror -pthread \
  tests/sqlite-persistent-pipeline-test.cpp host/sqlite-gantt-trace.cpp \
  host/sqlite-io-range-trace.cpp "$build/sqlite3.o" -ldl -o "$build/pipeline"
"$build/pipeline"
for limit in 256 488; do
  if [ "$limit" = 488 ]; then
    g++ -std=c++11 -O1 -Wall -Wextra -Werror -pthread -DGROUP_PMP_SQLITE_DESCRIPTOR_LIMIT=$limit \
      tests/sqlite-persistent-pipeline-test.cpp host/sqlite-gantt-trace.cpp \
      host/sqlite-io-range-trace.cpp "$build/sqlite3.o" -ldl -o "$build/pipeline-$limit"
    "$build/pipeline-$limit"
  fi
  gcc -std=gnu11 -O2 -Wall -Wextra -Werror -DGROUP_PMP_SQLITE_DESCRIPTOR_LIMIT=$limit \
    -Itests/include-shadow -I"$sdk" -Ieapp tests/sqlite-store-pipeline-test.c \
    eapp/group-pmp-crypto.c eapp/aes_core.c "$aead" -o "$build/store-$limit"
  "$build/store-$limit"
  g++ -std=c++11 -O1 -ffunction-sections -fdata-sections -Wl,--gc-sections -pthread \
    -DGROUP_PMP_SQLITE_DESCRIPTOR_LIMIT=$limit -Itests/include-shadow -I"$sdk" -Ieapp \
    tests/sqlite-csv-test.cpp host/sqlite-extent-io.cpp host/sqlite-gantt-trace.cpp \
    host/sqlite-io-range-trace.cpp "$build/sqlite3.o" -ldl -o "$build/csv-$limit"
  "$build/csv-$limit"
done
