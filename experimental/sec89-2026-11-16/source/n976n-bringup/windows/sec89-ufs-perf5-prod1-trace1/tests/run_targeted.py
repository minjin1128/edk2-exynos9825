#!/usr/bin/env python3
"""Run candidate checks inside the existing managed RAM launcher; export logs only."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--groups', nargs='+', choices=('view','lifecycle','core','scsi','bulk','ranges','production'), default=['view','lifecycle','core','scsi','bulk','ranges','production'])
    args = parser.parse_args()
    ram = Path(os.environ['N976N_RAM_SCRATCH_PATH']).resolve()
    assert ram.is_dir() and Path(os.environ['TMPDIR']).resolve() == ram
    args.evidence.mkdir(parents=True, exist_ok=False)
    start = time.monotonic()
    results = []
    for name in args.groups:
        output = ram/name
        command = [sys.executable, '-B', str(Path(__file__).with_name('test_'+name+'.py')),
                   '--out', str(output)]
        result = subprocess.run(command, text=True, capture_output=True, timeout=120)
        target = args.evidence/name
        shutil.copytree(output, target, ignore=shutil.ignore_patterns('cases', '*.dSYM'))
        report = json.loads((target/'report.json').read_text())
        if result.returncode:
            (target/'runner.log').write_text(result.stdout+result.stderr)
        results.append({'group':name, 'passed':result.returncode == 0 and report['passed'],
                        'cases':len(report['checks']), 'elapsed_seconds':report['elapsed_seconds']})
    summary = {'milestone':'SEC89 UFS PERF5', 'passed':all(r['passed'] for r in results),
        'groups':results, 'elapsed_seconds':time.monotonic()-start,
        'temporary_storage':'managed local RAM; compiled programs not retained',
        'omissions':['Fake scheduling/MMIO cannot establish real Windows timer, worker or hardware behavior',
                     'No native ARM64 build in this receipt',
                     'No physical Windows, bugcheck display, crash dump or media access',
                     'No comprehensive regression']}
    (args.evidence/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary))
    return 0 if summary['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
