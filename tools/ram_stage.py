# SPDX-License-Identifier: MIT
"""Isolated Orb tmpfs staging; helper bodies extracted from the verified path."""
import json
import os
from pathlib import Path
import subprocess
MACHINE = "ubuntu-amd64"
STAGE = None
STAGE_BUDGET = 4 * 1024 * 1024 * 1024

def run(*args: str, capture: bool = False) -> str:
    completed = subprocess.run(args, text=True, check=True,
                               stdout=subprocess.PIPE if capture else None)
    return completed.stdout.strip() if capture else ""

def orb(*args: str, capture: bool = False) -> str:
    return run("orb", "-m", MACHINE, *args, capture=capture)

def check_ram_stage(*, require_free: bool = False) -> dict:
    """Check the fixed tmpfs stage; never fall back to persistent temporary I/O.

    This is a pre/post-build capacity policy, not a hard tmpfs quota. The stage
    is retained in RAM for an explicitly requested incremental build.
    """
    script = '''import json, os, pathlib, shutil, sys
p = pathlib.Path(sys.argv[1]); budget = int(sys.argv[2])
assert p.parent == pathlib.Path('/dev/shm') and not p.is_symlink()
mounts = pathlib.Path('/proc/self/mountinfo').read_text().splitlines()
assert any(line.split()[4] == '/dev/shm' and
           line.split(' - ', 1)[1].split()[0] == 'tmpfs' for line in mounts), 'RAM stage requires tmpfs'
if p.exists():
    assert p.is_dir() and p.stat().st_uid == os.getuid(), 'RAM stage owner/type mismatch'
used = 0
for current, dirs, files in os.walk(p):
    for name in files:
        used += (pathlib.Path(current) / name).lstat().st_blocks * 512
assert used <= budget, 'RAM stage exceeded its 4 GiB checked budget'
free = shutil.disk_usage(p.parent).free
if sys.argv[3] == '1':
    assert free >= budget, 'Insufficient tmpfs headroom for the isolated EDK2 build'
print(json.dumps({'path': str(p), 'filesystem': 'tmpfs', 'allocated_bytes': used,
                  'budget_bytes': budget, 'free_bytes': free, 'hard_quota': False}))
'''
    return json.loads(orb("python3", "-c", script, STAGE, str(STAGE_BUDGET),
                          "1" if require_free else "0", capture=True))

def stream_tree(source: Path, destination: str, names: list[str]) -> None:
    """Stream trusted local source trees, avoiding a shared-folder build."""
    archive = subprocess.Popen(
        ["tar", "--no-xattrs", "-cf", "-", "--exclude=.git", "--exclude=__pycache__",
         "--exclude=.DS_Store", "-C", str(source), *names],
        stdout=subprocess.PIPE, env={**os.environ, "COPYFILE_DISABLE": "1"},
    )
    assert archive.stdout is not None
    extract = subprocess.run(
        ["orb", "-m", MACHINE, "tar", "-xf", "-", "-C", destination],
        stdin=archive.stdout, stdout=subprocess.DEVNULL,
    )
    archive.stdout.close()
    archive_code = archive.wait()
    if archive_code or extract.returncode:
        raise RuntimeError(f"Source staging failed: tar={archive_code}, extract={extract.returncode}")
