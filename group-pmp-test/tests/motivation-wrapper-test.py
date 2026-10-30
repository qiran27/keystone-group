import csv
import os
import pathlib
import shutil
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="motivation-wrapper-") as tmp:
    base = pathlib.Path(tmp)
    (base / "data").mkdir()
    (base / "motivation").mkdir()
    shutil.copy(root / "run-motivation-overlap.sh", base)
    shutil.copy(root / "run-motivation-architecture.sh", base)
    shutil.copy(root / "motivation/summarize.py", base / "motivation")
    runner = base / "group-pmp-test-runner"
    shutil.copy(root / "tests/motivation-mock-runner.py", runner)
    runner.chmod(0o755)
    for name in ("group-pmp-motivation-worker.eapp_riscv", "eyrie-rt", "loader.bin"):
        (base / name).write_text("keystone-worker-overlap-v7\nkeystone-motivation-protected-task-v4\n")
    for name in ("prepare-aes-benchmark-env.sh", "prepare-3w1hm-isolation.sh"):
        p = base / name
        p.write_text("#!/bin/sh\nprintf '%s\\n' \"$1\" >> helpers.log\n")
        p.chmod(0o755)
    env = dict(os.environ, GROUP_PMP_RUN_LOCK_DIR=str(base / "lock"))
    def run(reps, size, kind, output, fail=False):
        return subprocess.run(["sh", str(base / "run-motivation-overlap.sh"), str(reps), size, "hot",
                               str(base / "data"), str(base / output), kind],
                              env=dict(env, MOCK_FAIL=str(int(fail))), capture_output=True, text=True)
    fixed=runner.read_text()
    runner.write_text(fixed.replace('# keystone-motivation-epm-reservation-v2\n',''))
    stale=run(1,"60MB","diagnostic","stale")
    assert stale.returncode!=0 and 'matched EPM reservation fix' in stale.stderr
    assert not (base/'stale').exists() and not (base/'lock').exists()
    runner.write_text(fixed)
    runner.write_text(fixed.replace('# keystone-motivation-blocking-ocall-v4\n',''))
    stale=run(1,"60MB","diagnostic","stale-blocking")
    assert stale.returncode!=0 and 'blocking read OCALL contract' in stale.stderr
    runner.write_text(fixed)
    runner.write_text(fixed.replace('# keystone-motivation-shared-uring-v3\n',''))
    stale=run(1,"60MB","diagnostic","stale-transport")
    assert stale.returncode!=0 and 'shared SQLite/FIO io_uring' in stale.stderr
    runner.write_text(fixed)
    result = run(10, "sweep", "formal", "formal-out")
    assert result.returncode == 0, result.stdout + result.stderr
    folder = next((base / "formal-out").iterdir())
    with (folder / "samples.csv").open() as f: rows = list(csv.DictReader(f))
    assert len(rows) == 180
    for mb in (60, 100, 200, 300, 400, 500):
        group = [r for r in rows if int(r["input_bytes"]) == mb * 1000000]
        assert len(group) == 30
        assert [(r['mode'],r['worker_enclaves']) for r in group[:6]] == [
            ('sync','1'),('async','1'),('async','3'),('async','1'),('async','3'),('sync','1')]
    assert not list((base / "data").iterdir()) and not (base / "lock").exists()
    arch=subprocess.run(['sh',str(base/'run-motivation-architecture.sh'),'3','500MB','hot',
                         str(base/'data'),str(base/'architecture'),'formal'],env=env,capture_output=True,text=True)
    assert arch.returncode==0,arch.stdout+arch.stderr
    folder=next((base/'architecture').iterdir())
    with (folder/'samples.csv').open() as f: rows=list(csv.DictReader(f))
    assert len(rows)==12 and sum(r['diagnostic']=='0' for r in rows)==9
    assert all(r['csv_schema']=='8' and r['crypto_algorithm']=='aes-128-ecb' for r in rows)
    assert all(r['active_master']=='1' and r['tsr_dispatches']==r['worker_enclaves'] for r in rows)
    with (folder/'summary.csv').open() as f: summary=list(csv.DictReader(f))
    assert len(summary)==2 and {r['formal_eligible'] for r in summary}=={'0','1'}
    assert len(list(folder.glob('timeline-*.svg')))==1
    with (folder/'overlap-evidence.csv').open() as f: reports=list(csv.DictReader(f))
    assert len(reports)==3 and all(r['protected_tasks_complete']=='1' for r in reports)
    bad=folder/(reports[0]['run_id']+'-tasks.csv');bad.unlink()
    invalid=subprocess.run(['python3',str(base/'motivation/summarize.py'),str(folder)],capture_output=True,text=True)
    assert invalid.returncode!=0
    gcm=subprocess.run(['sh',str(base/'run-motivation-architecture.sh'),'--cipher','aes-gcm-128','1','60MB','hot',
                        str(base/'data'),str(base/'architecture-gcm'),'diagnostic'],env=env,capture_output=True,text=True)
    assert gcm.returncode==0,gcm.stdout+gcm.stderr
    folder=next((base/'architecture-gcm').iterdir())
    with (folder/'samples.csv').open() as f: gcm_rows=list(csv.DictReader(f))
    assert len(gcm_rows)==3 and all(r['crypto_algorithm']=='aes-128-gcm' and r['csv_schema']=='8' for r in gcm_rows)
    assert 'aes-gcm-128' in folder.name
    bad_cipher=subprocess.run(['sh',str(base/'run-motivation-architecture.sh'),'--cipher','invalid'],env=env,capture_output=True,text=True)
    assert bad_cipher.returncode==2
    block_sweep=subprocess.run(['sh',str(base/'run-motivation-architecture.sh'),'--block-size','sweep','1','60MB','hot',
                        str(base/'data'),str(base/'block-sweep'),'diagnostic'],env=env,capture_output=True,text=True)
    assert block_sweep.returncode==0,block_sweep.stdout+block_sweep.stderr
    folders=list((base/'block-sweep').iterdir());assert len(folders)==3
    sizes=set()
    for folder in folders:
        with (folder/'samples.csv').open() as f: block_rows=list(csv.DictReader(f))
        assert len(block_rows)==3
        sizes.add(int(block_rows[0]['block_bytes']))
        assert len({r['block_bytes'] for r in block_rows})==1
        with (folder/'overlap-evidence.csv').open() as f: stages=list(csv.DictReader(f))
        assert len(stages)==3 and all(float(r['full_byte_verify_ms_sum'])>0 for r in stages)
    assert sizes=={4096,16384,65536}
    invalid_block=subprocess.run(['sh',str(base/'run-motivation-architecture.sh'),'--block-size','8KB'],env=env,capture_output=True,text=True)
    assert invalid_block.returncode==2
    for size,expected in [('500MB',9),('sweep',54)]:
        output='three-'+size
        result=run(3,size,'formal',output)
        assert result.returncode==0,result.stdout+result.stderr
        folder=next((base/output).iterdir())
        with (folder/'samples.csv').open() as f: three=list(csv.DictReader(f))
        assert len(three)==expected and all(r['diagnostic']=='0' for r in three)
        with (folder/'summary.csv').open() as f: summary=list(csv.DictReader(f))
        assert len(summary)==(6 if size=='sweep' else 1)
        assert all(r['formal_eligible']=='1' and
                   all(r[m+'_valid_runs']=='3' for m in ('sync','async','async3')) for r in summary)
        assert not list((base/'data').iterdir()) and not (base/'lock').exists()
    assert run(1, "60MB", "formal", "invalid").returncode == 2
    assert run(2, "60MB", "formal", "invalid-two").returncode == 2
    assert run(1, "500MB", "diagnostic", "diag").returncode == 0
    diagdir=next((base/'diag').iterdir())
    with (diagdir/'samples.csv').open() as f: diagnostic=list(csv.DictReader(f))
    assert len(diagnostic)==3 and {r['worker_enclaves'] for r in diagnostic}=={'1','3'}
    assert all(r['input_bytes']=='500000000' for r in diagnostic)
    assert run(10, "60MB", "formal", "failed", True).returncode != 0
    faildir = next((base / "failed").iterdir())
    with (faildir / "samples.csv").open() as f: failures = list(csv.DictReader(f))
    assert len(failures) == 1 and failures[0]["result_ok"] == "0"
    assert not (faildir / "summary.csv").exists()
    assert not list((base / "data").iterdir()) and not (base / "lock").exists()
print("motivation wrapper: ten-round sweep, three-round 500MB/sweep (9/54 calls), diagnostic, failure retention and cleanup PASS")
