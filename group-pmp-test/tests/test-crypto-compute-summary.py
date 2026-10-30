import csv
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1]/'crypto-compute/summarize.py'
spec = importlib.util.spec_from_file_location('crypto_summary', MODULE)
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


class SummaryTests(unittest.TestCase):
    def test_startup_contract(self):
        root = MODULE.parents[1]
        host = (root/'host/crypto-compute.hpp').read_text()
        self.assertLess(host.index('!configure_default_group()'),
                        host.index('hart = sm_hart_id_for_cpu(1)'))
        self.assertLess(host.index('hart = sm_hart_id_for_cpu(1)'),
                        host.index('bind_and_enqueue(enclaves[1], hart)'))
        self.assertIn('CRYPTO_COMPUTE_FREE_BYTES);', host)
        self.assertNotIn('const uint64_t hart = sm_hart_id_for_cpu(1)', host)
        for path in ('eapp/crypto-compute.h', 'run-crypto-compute-bench.sh',
                     'rebuild-and-test.sh'):
            self.assertIn('keystone-crypto-compute-startup-v2', (root/path).read_text())

    def fixture(self, root, cipher='aes-ecb-128', size='60MB'):
        summary.make_plan(3, size, root/'plan.csv', cipher)
        with (root/'plan.csv').open() as f:
            plan = list(csv.DictReader(f))
        rows = []
        for p in plan:
            seconds = 1 + int(p['sample'])
            total = int(p['total_bytes'])
            rows.append({**p, 'version':1, 'worker_count':1, 'block_bytes':2000000,
                         'blocks':(total+1999999)//2000000, 'processed_bytes':total, 'wall_ticks':seconds*1000,
                         'cpu_ticks':seconds*900, 'cycles':seconds*2000, 'timebase_hz':1000,
                         'wall_seconds':seconds, 'cpu_seconds':seconds*0.9,
                         'descheduled_seconds':seconds*0.1, 'wall_mb_per_sec':total/1e6/seconds,
                         'cpu_mb_per_sec':total/1e6/(seconds*0.9), 'validated':1, 'error_code':0,
                         'data_io_operations':0, 'timed_ocalls':0,
                         'execution_environment':'riscv-worker-enclave',
                         'timing_scope':'sum-of-transform-intervals'})
        return rows

    def write(self, root, rows):
        with (root/'samples.csv').open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)

    def test_all_sizes_plan(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            summary.make_plan(3, 'sweep', root/'plan.csv')
            with (root/'plan.csv').open() as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 108)
            self.assertEqual([r['cipher'] for r in rows],
                             [c for c in summary.ALGORITHMS for _ in range(36)])
            self.assertEqual(len({(r['cipher'],r['operation'],r['total_bytes'],r['sample']) for r in rows}), 108)

    def test_each_cipher_independently(self):
        for cipher in summary.ALGORITHMS:
            with tempfile.TemporaryDirectory() as t:
                root = Path(t)
                summary.make_plan(3, 'sweep', root/'plan.csv', cipher)
                with (root/'plan.csv').open() as f:
                    rows = list(csv.DictReader(f))
                self.assertEqual(len(rows), 36)
                self.assertEqual({r['cipher'] for r in rows}, {cipher})
                subprocess.run(['sh', str(MODULE.parents[1]/'run-crypto-compute-bench.sh'),
                                '--cipher', cipher, '3', 'sweep', str(root/'cli')],
                               env={**os.environ, 'CRYPTO_COMPUTE_DRY_RUN':'1'},
                               check=True, capture_output=True, text=True)
                with next((root/'cli').glob('run-*/plan.csv')).open() as f:
                    cli_rows = list(csv.DictReader(f))
                self.assertEqual(cli_rows, rows)

    def test_real_min_median_max(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); rows = self.fixture(root); self.write(root, rows)
            summary.summarize(root)
            with (root/'summary.csv').open() as f:
                rs = list(csv.DictReader(f))
            self.assertEqual(len(rs), 2)
            self.assertEqual([float(rs[0]['wall_mb_per_sec_'+k]) for k in ('min','median','max')], [15,20,30])
            self.assertEqual(rs[0]['samples'], '3')
            with (root/'comparison.csv').open() as f:
                self.assertEqual(len(list(csv.DictReader(f))), 2)

    def test_all_cipher_comparison(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); rows = self.fixture(root, 'all', 'sweep'); self.write(root, rows)
            summary.summarize(root)
            with (root/'summary.csv').open() as f:
                results = list(csv.DictReader(f))
            self.assertEqual(len(rows), 108)
            self.assertEqual(len(results), 36)
            self.assertEqual({r['cipher'] for r in results}, set(summary.ALGORITHMS))
            with (root/'comparison.csv').open() as f:
                comparison = list(csv.DictReader(f))
            self.assertEqual(len(comparison), 12)
            for row in comparison:
                mb = int(row['total_mb'])
                for cipher in summary.ALGORITHMS:
                    self.assertEqual(row[cipher+'_samples'], '3')
                    self.assertEqual([float(row[cipher+'_wall_mb_per_sec_'+s])
                                      for s in ('min', 'median', 'max')], [mb/4, mb/3, mb/2])

    def test_missing_duplicate_failed_or_wrong_timing_rejected(self):
        for change in ('missing', 'duplicate', 'failed', 'bad-throughput'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as t:
                root = Path(t); rows = self.fixture(root)
                if change == 'missing': rows.pop()
                if change == 'duplicate': rows[-1] = dict(rows[0])
                if change == 'failed': rows[0]['validated'] = 0
                if change == 'bad-throughput': rows[0]['wall_mb_per_sec'] = 999
                self.write(root, rows)
                with self.assertRaises(AssertionError): summary.summarize(root)
                self.assertFalse((root/'summary.csv').exists())


if __name__ == '__main__': unittest.main()
