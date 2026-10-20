"""SEC49-only overlay; run on the restored, pinned RAM-stage source."""
import hashlib
from pathlib import Path
import sys

path = Path(sys.argv[1]) / "MdeModulePkg/Core/Dxe/Misc/MemoryProtection.c"
original = path.read_bytes()
if hashlib.sha256(original).hexdigest() != "50122e0d40252290ad06950cfe7c1f462e167122507bd8b6b14eb3a3f8152c9f":
    raise SystemExit("SEC49 NX overlay requires the pinned upstream file")
source = original.decode()
newline = "\r\n" if "\r\n" in source else "\n"
source = source.replace("\r\n", "\n")
needle = "  NewAttributes = GetPermissionAttributeForMemoryType (NewType);\n"
replacement = """  // SEC49: a code allocation is writable staging storage, not permission to
  // execute. Only the sealed-FV publication hook admits verified code as RO-X.
  // Do not change the type policy for already executing Core/CPU images.
  if ((OldType == EfiConventionalMemory) &&
      ((NewType == EfiLoaderCode) || (NewType == EfiBootServicesCode) ||
       (NewType == EfiRuntimeServicesCode))) {
    EFI_STATUS Status;
    Status = gCpu->SetMemoryAttributes (gCpu, Memory, Length, EFI_MEMORY_XP);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "SEC49 CODE ALLOCATION NX FAIL %r\\n", Status));
      for (;;) { CpuDeadLoop (); }
    }
    return Status;
  }

""" + needle
if source.count(needle) != 1:
    raise SystemExit("SEC49 NX overlay context mismatch; source was not changed")
path.write_bytes(source.replace(needle, replacement).replace("\n", newline).encode())
print("SEC49 allocation NX overlay: " + hashlib.sha256(original).hexdigest() +
      " -> " + hashlib.sha256(path.read_bytes()).hexdigest())
