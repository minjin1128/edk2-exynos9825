#!/usr/bin/env python3
"""Actual Device adapter boundary tests in owned managed RAM, with persistent evidence."""
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
              HERE/"WdkBatteryStub.h", SRC/"Device.c", SRC/"Connection.h", SRC/"DiagProtocol.h", SRC/"Charge.h", SRC/"Charge.c",SRC/"PowerSource.c",SRC/"PowerSource.h",SRC/"Bench.c", SRC/"Lease.c", SRC/"Lease.h", SRC/"Resources.h", SRC/"Backend.h", SRC/"Bus.h", SRC/"ClockShare.c", SRC/"ClockShare.h", HERE/"device-tests.c", *sorted((HERE/"device_mocks").glob("*.h")), Path(__file__)]
    adc=PROJECT/"common/sec89-charge-adcwin1"
    inputs += [SRC/"AdcWdf.c",SRC/"AdcWdf.h",adc/"Adc.c",adc/"Adc.h",adc/"AdcLease.h",adc/"ThermalContract.h"]
    thermal=PROJECT/"common/sec89-charge-thermal1"
    control=PROJECT/"common/sec89-charge-control3"
    inputs += [SRC/"ThermalBridge.c",SRC/"ThermalBridge.h",thermal/"Thermal.c",thermal/"Thermal.h",control/"ChargeControl.c",control/"ChargeControl.h",control/"tests/twrp_dt_fixture.h"]
    before = hashes(inputs)
    result = {"passed": False, "hardware_verified": False, "host": platform.platform(),
              "source_sha256": before, "runs": [],
              "coverage": ["exact raw/trans resources and pre-map rejection", "owned mapping/claim rollback and quarantine", "actual Device + ADC WDF IRQ lifecycle, 15 conversions, cancellation and join before unmap", "prepare-only retry and persistent consumed generation", "ADC failure keeps HSI cleanup ownership until IRQ disable", "join timeout fails closed without unmap", "class registration/notify callback reentry without StateLock", "consumed/completed/pending/forwarded IRP paths and IRQL", "fresh sampling failure invalidates class cache", "TOP readonly and fixed-MMIO write fence"],
              "omitted": ["actual Windows thread concurrency and WDF object lifetime", "real MMIO transport", "real Windows PnP arbitration and installation"]}
    start = time.monotonic()
    scratch = RamScratch(64)
    try:
        with scratch:
            env = dict(os.environ, TMPDIR=str(scratch.path))
            for name, flags in [("warnings-O2", ["-O2"]),
                                ("asan-ubsan-O1", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"])]:
                binary = scratch.path / name
                cmd = ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-DN976N_BATTERY_HOST_TEST", *flags,
                       "-I"+str(adc), str(adc/"Adc.c"), str(common/"N976nBattery.c"), str(SRC/"BatteryCache.c"), str(SRC/"Miniclass.c"),
                       "-I"+str(HERE/"device_mocks"), "-I"+str(common), str(SRC/"Lease.c"), str(SRC/"Charge.c"),str(SRC/"PowerSource.c"),str(SRC/"Bench.c"), str(SRC/"ClockShare.c"), "-I"+str(thermal), "-I"+str(control), str(SRC/"ThermalBridge.c"), str(thermal/"Thermal.c"),str(control/"ChargeControl.c"), str(HERE/"device-tests.c"), "-o", str(binary)]
                build = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
                run = {"name": name, "compile_return": build.returncode, "compile_stderr": build.stderr}
                result["runs"].append(run)
                if build.returncode:
                    raise RuntimeError("compile failed")
                tested = subprocess.run([str(binary)], env=env, capture_output=True, text=True, timeout=30)
                run.update(exit_code=tested.returncode, stdout=tested.stdout, stderr=tested.stderr)
                if tested.returncode:
                    raise RuntimeError("test failed")
                run["checks"] = int(re.search(r"PASS (\d+) checks", tested.stdout).group(1))
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
                      "cases": [r.get("checks") for r in result["runs"]]}))
    return 0 if result["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
