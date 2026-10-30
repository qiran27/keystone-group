#!/bin/sh
set -eu

# The historical filename is retained, but the driver now uses RISC-V
# exception-table-backed nofault loads/stores. A correct PMP denial returns a
# controlled EFAULT result instead of killing the kernel thread.
cd "$(dirname "$0")"
RUNNER=${GROUP_PMP_RUNNER:-./run-group-pmp-test.sh}
export GROUP_PMP_LEASE_TEST_FALLBACK=1
echo "[p9] starting recoverable host YXSTM access-denial probe"

GROUP_PMP_TEST_MODE=host-access exec "$RUNNER" "$@"
