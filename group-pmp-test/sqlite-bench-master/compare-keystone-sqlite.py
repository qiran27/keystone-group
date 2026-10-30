#!/usr/bin/env python3
import argparse
import csv
import re
import sys
from pathlib import Path

RESULT_RE = re.compile(r"^([A-Za-z0-9_]+)\s+:\s+([0-9.]+)\s+micros/op;")


def parse_log(path: Path) -> dict[str, float]:
    results: dict[str, float] = {}
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            match = RESULT_RE.match(line.strip())
            if match:
                results[match.group(1)] = float(match.group(2))
    if not results:
        raise SystemExit(f"no sqlite-bench workload results found in {path}")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare native/single-enclave/dual-enclave SQLite benchmark logs."
    )
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--single", type=Path)
    parser.add_argument("--dual", type=Path)
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args()

    native = parse_log(args.native)
    single = parse_log(args.single) if args.single else {}
    dual = parse_log(args.dual) if args.dual else {}

    rows = []
    workloads = sorted(set(native) | set(single) | set(dual))
    for workload in workloads:
        native_us = native.get(workload)
        single_us = single.get(workload)
        dual_us = dual.get(workload)
        if native_us is None:
            continue
        single_loss = (
            ((single_us - native_us) / native_us) * 100.0
            if single_us is not None
            else None
        )
        dual_loss = (
            ((dual_us - native_us) / native_us) * 100.0
            if dual_us is not None
            else None
        )
        rows.append(
            {
                "workload": workload,
                "native_us_per_op": native_us,
                "single_us_per_op": single_us,
                "single_loss_percent": single_loss,
                "dual_us_per_op": dual_us,
                "dual_loss_percent": dual_loss,
            }
        )

    fieldnames = [
        "workload",
        "native_us_per_op",
        "single_us_per_op",
        "single_loss_percent",
        "dual_us_per_op",
        "dual_loss_percent",
    ]
    out = args.csv.open("w", newline="", encoding="utf-8") if args.csv else sys.stdout
    try:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    finally:
        if args.csv:
            out.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
