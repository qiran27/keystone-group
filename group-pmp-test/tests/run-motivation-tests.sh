#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
build=$(mktemp -d /tmp/motivation-test-XXXXXXXX)
trap 'rm -rf "$build"' EXIT
python3 tests/extract-motivation-epm.py "$build/motivation-epm-driver.inc"
g++ -std=c++11 -O2 -Wall -Wextra -Werror -I"$build" tests/motivation-epm-test.cpp -o "$build/epm-test"
"$build/epm-test"
g++ -std=c++11 -O2 -Wall -Wextra -Werror -pthread tests/motivation-blocking-test.cpp -o "$build/blocking-test"
"$build/blocking-test" "$build"
archive=$(sh tests/build-benchmark-aead.sh "$build")
gcc -std=c11 -O2 -Wall -Wextra -Werror -I../../sdk/include -c motivation/architecture.c -o "$build/architecture.o"
g++ -std=c++11 -O2 -Wall -Wextra -Werror -pthread -I../../sdk/include \
  tests/motivation-architecture-test.cpp "$build/architecture.o" -o "$build/architecture-test"
"$build/architecture-test"
gcc -std=c11 -O2 -Wall -Wextra -Werror -DMBEDTLS_CONFIG_FILE='"aead-config.h"' \
  -Isecurity -Isecurity/vendor/mbedtls-3.6.7/include -c motivation/core.c -o "$build/core.o"
gcc -std=c11 -O2 -Wall -Wextra -Werror -c eapp/aes_core.c -o "$build/aes.o"
g++ -std=c++11 -O2 -Wall -Wextra -Werror -pthread tests/motivation-test.cpp \
  "$build/core.o" "$build/aes.o" "$archive" -o "$build/motivation-test"
"$build/motivation-test" "$build"
MOT_TEST_ECB=1 "$build/motivation-test" "$build"
status=0
MOT_TEST_SHARED_URING=1 "$build/motivation-test" "$build" || status=$?
if [ "$status" -eq 77 ]; then
  echo 'Motivation shared registered io_uring SKIP: unsupported local kernel; board run required'
elif [ "$status" -ne 0 ]; then
  exit "$status"
else
  MOT_TEST_ECB=1 MOT_TEST_SHARED_URING=1 "$build/motivation-test" "$build"
fi
gcc -std=gnu11 -fsyntax-only -Wall -Wextra -Werror -I../../sdk/include \
  -I../../sdk/include/app -I../../sdk/include/edge -Ieapp eapp/group-pmp-motivation-worker.c
python3 tests/motivation-summary-test.py
python3 tests/motivation-wrapper-test.py
sh tests/check-rv8-wrapper.sh
g++ -std=c++11 -fsyntax-only -pthread -Wall -Wextra -Werror -I../../sdk/include -I../../sdk/include/edge \
  -Ieapp -Ihost -iquote sqlite-bench-master host/group-pmp-test-runner.cpp
sh -n run-motivation-overlap.sh
sh -n run-motivation-architecture.sh
sh -n run-rv8-enclave-scaling.sh
bash -n rebuild-and-test.sh
echo 'Motivation native protocol and script tests PASS (not board performance)'
