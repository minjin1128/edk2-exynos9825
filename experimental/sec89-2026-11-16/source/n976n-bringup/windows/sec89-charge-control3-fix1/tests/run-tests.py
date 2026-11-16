#!/usr/bin/env python3
"""Actual cache + callback tests in owned managed RAM, with persistent evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SRC = HERE.parent
PROJECT = SRC.parents[1]
ROOT = PROJECT.parent
sys.path.insert(0, str(ROOT / "tools"))
from ram_scratch import RamScratch

def hashes(paths):
    return {str(p.relative_to(PROJECT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Choose new evidence path; previous results are preserved")
    common = PROJECT / "common/sec88-battery1"
    inputs = [common/"N976nBattery.h", common/"N976nBattery.c",
              SRC/"BatteryCache.h", SRC/"BatteryCache.c", SRC/"Miniclass.h", SRC/"Miniclass.c",
              HERE/"WdkBatteryStub.h", HERE/"frontend-tests.c", Path(__file__)]
    before = hashes(inputs)
    result = {"passed": False, "hardware_verified": False, "host": platform.platform(),
              "source_sha256": before, "runs": [],
              "coverage": ["D0 generation and obsolete worker exclusion", "start-based monotonic TTL and expiry without query",
                           "partial fields, known absent and unavailable presence", "tag continuity and invalidation",
                           "replay, clock rollback, malformed sample and counter boundaries",
                           "Battc callback output lengths, tags, errors and supplied locking",
                           "relative SOC with unknown design, rate, online and critical claims"],
              "omitted": ["live HSI45 bus ownership and transport", "Windows Battc runtime integration",
                          "real WDK ARM64 build", "device battery/charging protection or hardware validation"]}
    start = time.monotonic()
    scratch = RamScratch(64)
    try:
        with scratch:
            env = dict(os.environ, TMPDIR=str(scratch.path))
            for name, flags in [("warnings-O2", ["-O2"]),
                                ("asan-ubsan-O1", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"])]:
                binary = scratch.path / name
                cmd = ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-DN976N_BATTERY_HOST_TEST", "-I"+str(common), *flags,
                       str(common/"N976nBattery.c"), str(SRC/"BatteryCache.c"), str(SRC/"Miniclass.c"),
                       str(HERE/"frontend-tests.c"), "-o", str(binary)]
                build = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
                run = {"name": name, "compile_return": build.returncode, "compile_stderr": build.stderr}
                result["runs"].append(run)
                if build.returncode:
                    raise RuntimeError("compile failed")
                tested = subprocess.run([str(binary)], env=env, capture_output=True, text=True, timeout=30)
                run.update(exit_code=tested.returncode, stdout=tested.stdout, stderr=tested.stderr)
                if tested.returncode:
                    raise RuntimeError("test failed")
                run["cases"] = int(re.search(r"PASS (\d+) cases", tested.stdout).group(1))
            scratch.check()
            if before != hashes(inputs):
                raise RuntimeError("test inputs changed")
            result["passed"] = True
    except Exception as exc:
        result["error"] = repr(exc)
    result["ram"] = scratch.info
    result["seconds"] = time.monotonic() - start
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"passed": result["passed"], "output": str(args.output),
                      "cases": [r.get("cases") for r in result["runs"]]}))
    return 0 if result["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
