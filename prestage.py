"""Speculative preemption.

The predictor gives the next few syscall numbers.  Each number maps to the
subsystem it will run through, so the daemon can warm exactly that subsystem's
data before the process asks:

  fs  -> touch the files the class opened last time (dentry + page cache warm)
  vm  -> MADV_WILLNEED the class's largest mapping
  net -> nothing to stage; the call is recorded so the hit rate can report it

Nothing is executed on behalf of the process and no syscall is reordered. The
only effect is that pages are already in memory when the real call arrives.
"""

from __future__ import annotations

import ctypes
import os

import sigs

MADV_WILLNEED = 3
_libc = None


def _madvise(addr, length, advice):
    global _libc
    if _libc is None:
        try:
            _libc = ctypes.CDLL("libc.so.6", use_errno=True)
        except OSError:
            _libc = False
    if not _libc:
        return False
    return _libc.madvise(ctypes.c_void_p(addr), ctypes.c_size_t(length),
                         ctypes.c_int(advice)) == 0


class Prestage:
    def __init__(self):
        self.files = {}          # class -> tuple of recently opened paths
        self.warmed = 0
        self.issued = 0

    def remember_open(self, cls, path):
        if not path:
            return
        kept = list(self.files.get(cls, ()))
        if path in kept:
            return
        kept.append(path)
        self.files[cls] = tuple(kept[-8:])

    def warm(self, cls, predicted, proc=None):
        """Pre-stage for the predicted syscalls. Returns pages warmed."""
        self.issued += 1
        warmed = 0
        kinds = {name for nr in predicted for name in sigs.subsystems(nr)}
        if "fs" in kinds:
            warmed += self._warm_files(cls)
        if "vm" in kinds and proc is not None:
            warmed += self._warm_maps(proc)
        self.warmed += warmed
        return warmed

    def _warm_files(self, cls):
        warmed = 0
        for path in self.files.get(cls, ()):
            try:
                with open(path, "rb") as fh:
                    fh.read(4096)
                warmed += 1
            except OSError:
                continue
        return warmed

    @staticmethod
    def _warm_maps(proc):
        """MADV_WILLNEED over the process's largest private mappings."""
        warmed = 0
        try:
            with open(f"/proc/{proc}/maps", encoding="utf-8", errors="replace") as fh:
                rows = []
                for line in fh:
                    parts = line.split()
                    if len(parts) < 2 or "r" not in parts[1]:
                        continue
                    try:
                        start, end = (int(x, 16) for x in parts[0].split("-"))
                    except ValueError:
                        continue
                    rows.append((end - start, start, end))
        except OSError:
            return 0
        rows.sort(reverse=True)
        for _, start, end in rows[:4]:
            if _madvise(start, end - start, MADV_WILLNEED):
                warmed += max(1, (end - start) // 4096)
        return warmed

    def summary(self):
        return {"warmed": self.warmed, "issued": self.issued}
