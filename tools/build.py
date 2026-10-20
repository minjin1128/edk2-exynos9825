# SPDX-License-Identifier: MIT
"""Build and statically audit the extracted SEC68 sources; never flash a device."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

TOOLS = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("n976n", "qemu"), required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--system-image", type=Path, required=True)
    parser.add_argument("--seal-directory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--machine", default="ubuntu-amd64")
    args = parser.parse_args()
    scratch = os.environ.get("N976N_RAM_SCRATCH_PATH")
    if not scratch or Path(tempfile.gettempdir()).resolve() != Path(scratch).resolve():
        parser.error("Run through tools/ram_scratch.py; disk temporary fallback is prohibited")
    out = args.out.resolve()
    if out.exists() or out.is_symlink():
        parser.error("Choose a new output directory; existing builds are preserved")
    out.mkdir(parents=True)
    started = time.monotonic()
    report = {"baseline": "SEC68 source extraction", "profile": args.profile,
              "hardware_verified": False, "final_qualified": False,
              "firmware_executed": False, "device_accessed": False,
              "checks": [], "passed": False}
    commands = [
        ["build_platform.py", "--profile", args.profile, "--query-sequence", "system-windows",
         "--inputs", str(args.inputs.resolve()), "--system-image", str(args.system_image.resolve()),
         "--system-seal-directory", str(args.seal_directory.resolve()), "--out", str(out / "fv"), "--machine", args.machine],
        ["build_entry.py", "--edk2-build", str(out / "fv"), "--out", str(out / "entry"), "--machine", args.machine],
        ["check_fv.py", "--fv", str(out / "fv/DXE.Fv"), "--inventory", str(out / "fv/inventory.json"), "--output", str(out / "fv-check.json")],
    ]
    try:
        for name, *arguments in commands:
            phase = time.monotonic()
            subprocess.run([sys.executable, "-B", str(TOOLS / name), *arguments], check=True)
            report["checks"].append({"tool": name, "passed": True, "seconds": time.monotonic() - phase})
        report["passed"] = True
    finally:
        report["seconds"] = time.monotonic() - started
        (out / "build-result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
