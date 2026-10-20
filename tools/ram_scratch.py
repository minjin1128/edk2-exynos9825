#!/usr/bin/env python3
"""Run disposable test I/O on verified RAM storage, never a disk fallback.

Linux uses an existing tmpfs; its per-run budget is sampled, not a hard quota.
Darwin creates a bounded, non-journaled RAM disk unless a verified RAM base is
provided. Memory/swap guards are sampled and do not promise zero SSD writes.
Persistent results must be written outside the RAM filesystem explicitly.
Python children must inherit PYTHONPATH/site initialization; -E/-I/-S or clearing
the launcher environment bypasses the supported Python no-fallback contract.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

MIB = 1024 * 1024
MAX_PATH_BYTES = 55


class ScratchError(RuntimeError):
    pass


def _run(argv, timeout=30):
    try:
        result = subprocess.run(argv, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScratchError(f"Command failed: {argv[0]}: {exc}") from exc
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()[:1000]
        raise ScratchError(f"Command failed ({result.returncode}): {argv[0]}: {detail}")
    return result.stdout


def _memory_sample(system):
    if system == "Linux":
        mem = dict(re.findall(r"^(\w+):\s+(\d+) kB$", Path("/proc/meminfo").read_text(), re.M))
        vm = dict(line.split() for line in Path("/proc/vmstat").read_text().splitlines())
        return {"total_bytes": int(mem["MemTotal"]) * 1024,
                "available_bytes": int(mem["MemAvailable"]) * 1024,
                "swap_out_bytes": int(vm["pswpout"]) * os.sysconf("SC_PAGE_SIZE"),
                "pressure_ok": True, "availability_method": "MemAvailable"}
    if system == "Darwin":
        vm = _run(["/usr/bin/vm_stat"]).decode()
        page_size = int(re.search(r"page size of (\d+) bytes", vm).group(1))
        pages = {key: int(value) for key, value in re.findall(r"^([^:\n]+):\s+(\d+)\.", vm, re.M)}
        available = sum(pages[key] for key in ("Pages free", "Pages inactive", "Pages speculative"))
        pressure = int(_run(["/usr/sbin/sysctl", "-n", "kern.memorystatus_vm_pressure_level"]))
        return {"total_bytes": int(_run(["/usr/sbin/sysctl", "-n", "hw.memsize"])),
                "available_bytes": available * page_size,
                "swap_out_bytes": pages["Swapouts"] * page_size,
                "pressure_ok": pressure == 1, "pressure_level": pressure,
                "availability_method": "free+inactive+speculative (estimate)"}
    raise ScratchError(f"Unsupported host: {system}")


def _linux_mount(path):
    path = Path(path).resolve(strict=True)
    matches = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields, filesystem = before.split(), after.split()
        mount = Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4]))
        if path == mount or mount in path.parents:
            matches.append((len(str(mount)), {"backing": filesystem[0],
                            "mountpoint": str(mount), "device": fields[2]}))
    if not matches:
        raise ScratchError(f"Cannot determine filesystem backing: {path}")
    return max(matches, key=lambda item: item[0])[1]


def _hdi_images():
    return plistlib.loads(_run(["/usr/bin/hdiutil", "info", "-plist"])).get("images", [])


def _image_devices(image):
    return {entity.get("dev-entry") for entity in image.get("system-entities", [])} - {None}


def _darwin_disk_info(path):
    # diskutil accepts the mount root, but not arbitrary directories below it.
    mount = Path(path).resolve(strict=True)
    device = mount.stat().st_dev
    while mount.parent != mount and mount.parent.stat().st_dev == device:
        mount = mount.parent
    return plistlib.loads(_run(["/usr/sbin/diskutil", "info", "-plist", str(mount)]))


def _darwin_ram_device(path):
    disk = _darwin_disk_info(path)
    device = disk.get("DeviceNode", "")
    whole = "/dev/" + disk.get("ParentWholeDisk", disk.get("DeviceIdentifier", ""))
    for image in _hdi_images():
        if re.fullmatch(r"ram://\d+", image.get("image-path", "")):
            if {device, whole} & _image_devices(image):
                return whole
    raise ScratchError(f"Not a verified hdiutil RAM disk: {path}")


def verify_ram_path(path):
    """Return independently checked backing information, or fail closed."""
    path = Path(path).resolve(strict=True)
    if not path.is_dir():
        raise ScratchError(f"Scratch base is not a directory: {path}")
    system = platform.system()
    if system == "Linux":
        backing = _linux_mount(path)
        if backing["backing"] != "tmpfs":
            raise ScratchError(f"Scratch must be tmpfs, found {backing['backing']}: {path}")
        return backing
    if system == "Darwin":
        device = _darwin_ram_device(path)
        disk = _darwin_disk_info(path)
        return {"backing": "hdiutil-ram", "device": device, "mountpoint": disk["MountPoint"]}
    raise ScratchError(f"Unsupported host: {system}")


def _linux_process_birth(pid):
    # The parenthesized process name may itself contain spaces or ')'.
    tail = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(tail[19])  # starttime is field 22; tail begins at field 3.


def _linux_preexisting_processes():
    result = {}
    for proc in Path("/proc").iterdir():
        if proc.name.isdigit():
            try:
                if proc.stat().st_uid == os.geteuid():
                    result[int(proc.name)] = _linux_process_birth(int(proc.name))
            except (OSError, ValueError, IndexError):
                pass  # Unknown identities are never eligible for the exception.
    return result


def _scratch_users(path, preexisting=None, ignored=None):
    """Find surviving users before removing memory still used by a child."""
    prefix = str(path)
    users = set()
    if platform.system() == "Linux":
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit() or int(proc.name) == os.getpid():
                continue
            try:
                if proc.stat().st_uid != os.geteuid():
                    continue
                if prefix.encode() in (proc / "cmdline").read_bytes():
                    users.add(int(proc.name))
                targets = [proc / "cwd", proc / "root", *list((proc / "fd").iterdir())]
                for target in targets:
                    try:
                        destination = os.readlink(target)
                    except FileNotFoundError:
                        continue  # A closing descriptor must not hide the other descriptors.
                    if destination.startswith(prefix + "/") or destination == prefix:
                        users.add(int(proc.name))
            except FileNotFoundError:
                continue  # Process exited during inspection.
            except PermissionError as exc:
                # Unreadable processes born before scratch existed cannot be
                # descendants launched by this run. Never exempt a reused PID.
                try:
                    same_existing = (int(proc.name) in (preexisting or {}) and
                                     preexisting[int(proc.name)] == _linux_process_birth(int(proc.name)))
                except (OSError, ValueError, IndexError):
                    same_existing = False
                if same_existing:
                    if ignored is not None:
                        ignored.append(int(proc.name))
                    continue
                raise ScratchError(f"Cannot inspect potential scratch user {proc.name}") from exc
        return sorted(users)
    result = subprocess.run(["/usr/sbin/lsof", "-t", "+D", prefix], capture_output=True, timeout=15)
    if result.returncode not in (0, 1) or result.stderr.strip():
        raise ScratchError("Cannot establish that RAM scratch has no surviving users")
    users.update(int(pid) for pid in result.stdout.split())
    for line in _run(["/bin/ps", "-axo", "pid=,command="]).decode().splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and prefix in fields[1]:
            users.add(int(fields[0]))
    return sorted(users - {os.getpid()})


def _allocated_bytes(path):
    total = 0
    for root, directories, files in os.walk(path, followlinks=False):
        for name in [*directories, *files]:
            try:
                total += os.lstat(Path(root) / name).st_blocks * 512
            except FileNotFoundError:
                pass
    return total


class RamScratch:
    def __init__(self, size_mib=1024, base=None):
        if not isinstance(size_mib, int) or isinstance(size_mib, bool) or size_mib < 64:
            raise ScratchError("size_mib must be an integer of at least 64 MiB")
        self.size_mib, self.base = size_mib, base
        self.budget = size_mib * MIB
        self.spare = min(64 * MIB, self.budget // 8)
        self.path = None
        self._device = None
        self._ram_url = None
        self._volume_uuid = None
        self._attachment_unproven = False
        self._preexisting_processes = {}
        self._identity = None
        self.info = {"budget_bytes": self.budget, "guard": "sampled; not a zero-write guarantee",
                     "cleanup": "not-started", "samples": 0}

    def _create_darwin(self):
        before = set().union(*(_image_devices(image) for image in _hdi_images()))
        ram_url = f"ram://{self.budget // 512}"
        self._attachment_unproven = True
        attached = plistlib.loads(_run(["/usr/bin/hdiutil", "attach", "-nomount", "-plist", ram_url]))
        candidates = {entity.get("dev-entry", "") for entity in attached.get("system-entities", [])}
        self.info["attach_returned_devices"] = sorted(candidates)
        candidates = {dev for dev in candidates if re.fullmatch(r"/dev/disk\d+", dev) and dev not in before}
        proven = set().union(*(_image_devices(image) for image in _hdi_images()
                              if image.get("image-path") == ram_url))
        if len(candidates) != 1 or not candidates <= proven:
            raise ScratchError("New RAM device identity could not be proven; nothing was formatted")
        self._device = candidates.pop()
        self._attachment_unproven = False
        self._ram_url = ram_url
        self.info["created_device"] = self._device
        label = "nr-" + uuid.uuid4().hex[:10]
        _run(["/usr/sbin/diskutil", "eraseVolume", "HFS+", label, self._device], timeout=60)
        disk = plistlib.loads(_run(["/usr/sbin/diskutil", "info", "-plist", self._device]))
        self._volume_uuid = disk.get("VolumeUUID")
        mount = Path(disk["MountPoint"]).resolve(strict=True)
        if mount != Path("/Volumes") / label or _darwin_ram_device(mount) != self._device:
            raise ScratchError("New RAM disk mount identity mismatch")
        os.chmod(mount, 0o700)
        (mount / ".metadata_never_index").touch()
        return mount

    def __enter__(self):
        if self.info["cleanup"] != "not-started":
            raise ScratchError("RamScratch instances cannot be reused")
        self.info["cleanup"] = "pending"
        try:
            self.system = platform.system()
            sample = _memory_sample(self.system)
            self.reserve = max(512 * MIB, sample["total_bytes"] // 20)
            self._swap_start = sample["swap_out_bytes"]
            self.info.update({"host": self.system, "memory_initial": sample,
                              "memory_reserve_bytes": self.reserve})
            if not sample["pressure_ok"] or sample["available_bytes"] < self.budget + self.reserve:
                raise ScratchError("Insufficient memory headroom or active memory pressure")
            if self.system == "Linux":
                self._preexisting_processes = _linux_preexisting_processes()
                self.info["preexisting_process_count"] = len(self._preexisting_processes)
            if self.base is not None:
                base = Path(self.base).resolve(strict=True)
            elif self.system == "Darwin":
                base = self._create_darwin()
            elif self.system == "Linux":
                base = None
                for candidate in (Path("/dev/shm"), Path("/tmp")):
                    try:
                        verify_ram_path(candidate)
                        fs = os.statvfs(candidate)
                        if fs.f_bavail * fs.f_frsize < self.budget + self.spare:
                            continue
                        base = candidate
                        break
                    except (ScratchError, OSError):
                        continue
                if base is None:
                    raise ScratchError("No verified tmpfs found; disk fallback is forbidden")
            else:
                raise ScratchError(f"Unsupported host: {self.system}")
            self.info.update(verify_ram_path(base))
            fs = os.statvfs(base)
            required = self.spare if self._device else self.budget + self.spare
            if fs.f_bavail * fs.f_frsize < required:
                raise ScratchError("Insufficient free space on the verified RAM filesystem")
            self.path = Path(tempfile.mkdtemp(prefix="nr-", dir=base))
            os.chmod(self.path, 0o700)
            identity = self.path.stat()
            self._identity = (identity.st_dev, identity.st_ino)
            self.info.update({"path": str(self.path), "capacity_bytes": fs.f_blocks * fs.f_frsize,
                              "budget_enforcement": "filesystem+sampled" if self._device else "sampled (no per-directory hard quota)"})
            if len(os.fsencode(self.path)) > MAX_PATH_BYTES:
                raise ScratchError("RAM scratch path exceeds 55 bytes; use a shorter base for Unix sockets")
            self.check()
            return self
        except BaseException:
            self._cleanup()
            raise

    def environment(self, base_env=None):
        if self.path is None or self.info["cleanup"] != "pending":
            raise ScratchError("RAM scratch is not active")
        env = dict(os.environ if base_env is None else base_env)
        env.update({key: str(self.path) for key in ("TMPDIR", "TMP", "TEMP")})
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        bootstrap = Path(__file__).resolve().parent / "ram_bootstrap"
        if not (bootstrap / "sitecustomize.py").is_file():
            raise ScratchError("Persistent Python RAM bootstrap is missing")
        env["PYTHONPATH"] = str(bootstrap) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        env["N976N_RAM_SCRATCH_PATH"] = str(self.path)
        env["N976N_RAM_SCRATCH_DEV"] = str(self._identity[0])
        env["N976N_RAM_SCRATCH_INO"] = str(self._identity[1])
        self.info["python_tempfile_policy"] = "persistent sitecustomize pins tempfile.tempdir; inherited environment required"
        return env

    def check(self):
        if self.path is None or self.info["cleanup"] != "pending":
            raise ScratchError("RAM scratch is not active")
        identity = self.path.lstat()
        if not stat.S_ISDIR(identity.st_mode) or (identity.st_dev, identity.st_ino) != self._identity:
            raise ScratchError("Owned scratch directory identity changed")
        sample = _memory_sample(self.system)
        fs = os.statvfs(self.path)
        used = _allocated_bytes(self.path)
        self.info.update({"memory_latest": sample, "available_bytes": fs.f_bavail * fs.f_frsize,
                          "allocated_bytes": used, "samples": self.info["samples"] + 1,
                          "peak_allocated_bytes": max(used, self.info.get("peak_allocated_bytes", 0)),
                          "swap_out_delta_bytes": sample["swap_out_bytes"] - self._swap_start})
        if not sample["pressure_ok"] or sample["available_bytes"] < self.reserve:
            raise ScratchError("Memory headroom/pressure guard failed")
        if sample["swap_out_bytes"] > self._swap_start:
            raise ScratchError("System swap-out increased; stop to avoid moving scratch writes to swap")
        if used > self.budget or fs.f_bavail * fs.f_frsize < self.spare:
            raise ScratchError("RAM scratch budget/free-space guard failed")

    def _cleanup(self):
        if self._attachment_unproven:
            self.info["cleanup"] = "refused: attachment identity unproven; inspect hdiutil info manually"
            raise ScratchError(self.info["cleanup"])
        if self.path is not None:
            exists = os.path.lexists(self.path)
            if exists:
                identity = self.path.lstat()
                if not stat.S_ISDIR(identity.st_mode) or (identity.st_dev, identity.st_ino) != self._identity:
                    self.info["cleanup"] = "refused: directory identity changed"
                    raise ScratchError(self.info["cleanup"])
            try:
                users = _scratch_users(self.path, self._preexisting_processes,
                                       self.info.setdefault("unreadable_preexisting_pids", []))
            except (OSError, ScratchError, subprocess.SubprocessError) as exc:
                self.info["cleanup"] = "refused: scratch users could not be checked"
                self.info["cleanup_error"] = str(exc)
                raise ScratchError(f"{self.info['cleanup']}: {exc}") from exc
            if users:
                self.info.update({"cleanup": "refused: surviving scratch users", "surviving_pids": users})
                raise ScratchError(f"Scratch retained for surviving processes {users}: {self.path}")
            if exists:
                shutil.rmtree(self.path)
        if self._device is not None:
            # Only the newly created and proven RAM device is ever detached.
            try:
                still_owned = any(image.get("image-path") == self._ram_url and self._device in _image_devices(image)
                                  for image in _hdi_images())
                if self._volume_uuid is not None:
                    disk = plistlib.loads(_run(["/usr/sbin/diskutil", "info", "-plist", self._device]))
                    still_owned = still_owned and disk.get("VolumeUUID") == self._volume_uuid
                if not still_owned:
                    raise ScratchError("RAM device identity changed; detach refused")
                _run(["/usr/bin/hdiutil", "detach", self._device], timeout=30)
            except ScratchError:
                self.info["cleanup"] = "failed: RAM device could not be detached"
                raise
            self._device = None
        self.info["cleanup"] = "complete"

    def __exit__(self, exc_type, exc, traceback):
        self._cleanup()


def _stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def _write_report(report, data):
    """Publish a small report without replacing an existing evidence file."""
    report.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".ram-report-", dir=report.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
        os.link(temporary, report)  # Atomic no-replace publication, also on POSIX macOS.
    finally:
        os.unlink(temporary)


def _check_report_destination(report):
    if os.path.lexists(report):
        raise ScratchError("Report already exists; choose a new path to preserve previous evidence")
    ancestor = report.parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    if platform.system() == "Linux":
        if _linux_mount(ancestor)["backing"] in ("tmpfs", "ramfs"):
            raise ScratchError("Report must be on persistent storage, outside RAM filesystems")
    elif platform.system() == "Darwin":
        try:
            _darwin_ram_device(ancestor)
        except ScratchError as exc:
            if not str(exc).startswith("Not a verified hdiutil RAM disk:"):
                raise
        else:
            raise ScratchError("Report must be on persistent storage, outside RAM filesystems")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size-mib", type=int, default=1024)
    parser.add_argument("--base")
    parser.add_argument("--report", required=True, help="Persistent JSON outside the RAM filesystem")
    parser.add_argument("--timeout-seconds", type=float, default=None)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or (args.timeout_seconds is not None and args.timeout_seconds <= 0):
        parser.error("A command and a positive optional timeout are required")
    if any(re.match(r"(?:TMPDIR|TMP|TEMP|PYTHONPATH|N976N_RAM_SCRATCH_\w+)=", token) for token in command):
        parser.error("Command may not override RAM temporary-storage or bootstrap environment")
    report = Path(args.report).expanduser().resolve()
    try:
        scratch = RamScratch(args.size_mib, args.base)
    except ScratchError as exc:
        print(f"ram_scratch: {exc}", file=sys.stderr)
        return 125
    interrupted = {"signal": None}
    previous = {}
    start = time.monotonic()
    exit_code = 125
    process = None
    report_allowed = False
    try:
        _check_report_destination(report)
        report_allowed = True
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, lambda signum, frame: interrupted.update(signal=signum))
        with scratch:
            mount = Path(scratch.info["mountpoint"])
            if report == mount or mount in report.parents:
                report_allowed = False
                raise ScratchError("Report must be outside the RAM filesystem")
            env = scratch.environment()
            resolved = subprocess.run([sys.executable, "-B", "-c", "import tempfile; print(tempfile.tempdir)"],
                                      env=env, capture_output=True, text=True, timeout=15, check=True).stdout.strip()
            if Path(resolved).resolve() != scratch.path:
                raise ScratchError("Child Python did not pin tempfile.tempdir to the verified RAM TMPDIR")
            if interrupted["signal"] is None:
                process = subprocess.Popen(command, env=env, start_new_session=True)
                try:
                    while True:
                        if interrupted["signal"] is not None:
                            exit_code = 128 + interrupted["signal"]
                            break
                        elapsed = time.monotonic() - start
                        if args.timeout_seconds is not None and elapsed >= args.timeout_seconds:
                            exit_code = 124
                            scratch.info["error"] = "Command timeout"
                            break
                        interval = 5 if args.timeout_seconds is None else min(5, args.timeout_seconds - elapsed)
                        try:
                            result = process.wait(timeout=max(0.01, interval))
                        except subprocess.TimeoutExpired:
                            scratch.check()
                            continue
                        scratch.check()
                        exit_code = result if result >= 0 else 128 - result
                        scratch.info["child_exit_code"] = result
                        break
                finally:
                    _stop_group(process)
                    scratch.info.setdefault("child_exit_code", process.returncode)
            else:
                exit_code = 128 + interrupted["signal"]
    except (ScratchError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        scratch.info["error"] = str(exc)
        print(f"ram_scratch: {exc}", file=sys.stderr)
        exit_code = 125
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        scratch.info.update({"exit_code": exit_code, "elapsed_seconds": round(time.monotonic() - start, 3),
                             "command": command, "signal": interrupted["signal"]})
        if report_allowed:
            try:
                _write_report(report, scratch.info)
            except OSError as exc:
                print(f"ram_scratch: report write failed: {exc}", file=sys.stderr)
                exit_code = 125
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
