"""Run the diagnostic wrapper against a mock runner, without board state."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    shutil.copy2(root / 'run-sqlite-neighbor-diagnostic.sh', work)
    (work / 'group-pmp-test-runner').write_text('keystone-sqlite-neighbor-admission-diagnostic-v2')
    (work / 'run-p10-mixed-scaling.sh').write_text('''#!/bin/sh
set -eu
[ "$GROUP_PMP_SQLITE_NEIGHBOR_ONLY" = 1 ]
[ "$GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC" = 1 ]
[ "$GROUP_PMP_SQLITE_NEIGHBOR_WORKERS" = 15 ]
[ "$GROUP_PMP_SQLITE_NEIGHBOR_SAMPLE" = 1 ]
[ "$*" = 'sqlite-bench adaptive-extent 15 1 512MB cold' ]
printf '%s\\n' "$GROUP_PMP_SQLITE_NEIGHBOR_WORKLOAD" >> calls
: > "$GROUP_PMP_SQLITE_GANTT_CSV"
''')
    command = ['sh',str(work/'run-sqlite-neighbor-diagnostic.sh'),'15','512MB','both',str(work/'output')]
    assert subprocess.run(command, capture_output=True).returncode == 0
    assert (work/'calls').read_text().splitlines() == ['6','8']
    assert subprocess.run(command, capture_output=True).returncode != 0
    assert (work/'calls').read_text().splitlines() == ['6','8']
    (work/'group-pmp-test-runner').write_text('old runner')
    assert subprocess.run(command, capture_output=True).returncode != 0
    command[2]='0'
    assert subprocess.run(command, capture_output=True).returncode != 0
print('Diagnostic wrapper: two selected cases, separate files, no overwrite, old runner rejected PASS')
