"""Fail closed and pin tempfile storage for Python children of ram_scratch.

This file lives outside scratch so a missing/unmounted RAM directory cannot
silently disable the guard when another Python child starts.
"""

import os as _os

try:
    import stat as _stat
    import tempfile as _tempfile

    _path = _os.environ["N976N_RAM_SCRATCH_PATH"]
    _identity = (int(_os.environ["N976N_RAM_SCRATCH_DEV"]),
                 int(_os.environ["N976N_RAM_SCRATCH_INO"]))
    _current = _os.lstat(_path)
    if not _stat.S_ISDIR(_current.st_mode) or (_current.st_dev, _current.st_ino) != _identity:
        raise RuntimeError("RAM scratch directory identity changed")
    if any(_os.environ.get(_key) != _path for _key in ("TMPDIR", "TMP", "TEMP")):
        raise RuntimeError("RAM temporary-storage environment changed")
    # Setting tempdir avoids tempfile's automatic disk fallback when RAM is full.
    _tempfile.tempdir = _path
except BaseException as _error:
    try:
        _os.write(2, ("ram_scratch: Python tempfile guard failed: " + str(_error) + "\n").encode())
    finally:
        # Python ignores ordinary sitecustomize exceptions, so raising is unsafe.
        _os._exit(125)
