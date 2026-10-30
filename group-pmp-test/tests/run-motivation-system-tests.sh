#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
build=$(mktemp -d /tmp/motivation-system-tests-XXXXXXXX)
trap 'rm -rf "$build"' EXIT
g++ -std=c++11 -O2 -Wall -Wextra -Werror tests/motivation-system-host-test.cpp -o "$build/host-test"
"$build/host-test" "$build"
python3 tests/motivation-system-test.py
sh -n run-motivation-system.sh
sh -n run-p10-mixed-scaling.sh
bash -n rebuild-and-test.sh
echo 'Extent-I/O real-system orchestration, statistics and timeline guards PASS (native fixtures, not board measurements)'
