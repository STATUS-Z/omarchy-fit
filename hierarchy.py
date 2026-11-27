"""Conditional memory hierarchy.

Hot facts are the pages a process touches between samples.  Cold inference is
the pages that are resident but unreferenced.  The split is read from the
kernel, per process, at a cost of one probe per mapping — not a walk of every
page.

Two documented interfaces:

  /proc/<pid>/pagemap   one 8-byte entry per virtual page; bit 63 present, bits
                        0-54 the physical frame number
  /proc/kpageflags      one 8-byte entry per frame; bit 25 KPF_IDLE, bit 2
                        KPF_REFERENCED

So the probe is: take one page from each VMA (a stride, not every page), read
its pagemap entry, then read that frame's flags.  Idle frames are cold; the
rest are hot facts.  Probe count is O(mappings) = O(log n) in pages.

Hot pages are then addressed by membership in the class cgroup, which is O(1):
the kernel either has the frame mapped for that cgroup or it does not, and the
lookup is the page-table walk it was already doing.  Cold pages are the ones
that will need fault resolution, and `memory.min` on the hot cgroup is what
keeps the hot side from being reclaimed first.
"""

from __future__ import annotations

import os
import struct

import config

_ENTRY = 8
_PRESENT = 1 << 63
_PFN = (1 << 55) - 1
_KPF_REFERENCED = 1 << 2
_KPF_IDLE = 1 << 25


def _prefetch(fh, offsets):
    """Read 8 bytes at each offset; returns list of ints or None."""
    out = []
    for off in offsets:
        try:
            fh.seek(off)
            raw = fh.read(_ENTRY)
        except OSError:
            out.append(None)
            continue
        out.append(struct.unpack("<Q", raw)[0] if len(raw) == _ENTRY else None)
    return out


class Hierarchy:
    def __init__(self):
        self.pagemap_ok = os.path.exists("/proc/self/pagemap")
        self.kpage_ok = os.path.exists("/proc/kpageflags")
        self.samples = 0
        self.probes = 0
        self.hot_mb = 0.0
        self.cold_mb = 0.0
        self.hot_frac = 0.0

    def available(self):
        return self.pagemap_ok and self.kpage_ok

    def split(self, pid, vmas, page_kb):
        """Return (hot_mb, cold_mb, probes) for one process.

        vmas is a list of (start, end) readable mappings.  At most VMA_PROBES
        of them are sampled, one page each.
        """
        resident = self._resident(pid, vmas, page_kb)
        if not vmas or not self.available():
            self.hot_mb, self.cold_mb = resident, 0.0
            return self.hot_mb, self.cold_mb, 0

        step = max(1, len(vmas) // config.VMA_PROBES)
        picks = vmas[::step][: config.VMA_PROBES]
        offsets = [(start // 4096) * _ENTRY for start, _ in picks]
        hot = cold = 0
        try:
            with open(f"/proc/{pid}/pagemap", "rb", buffering=0) as pm, \
                 open("/proc/kpageflags", "rb", buffering=0) as kf:
                for entry in _prefetch(pm, offsets):
                    if entry is None or not entry & _PRESENT:
                        continue
                    pfn = entry & _PFN
                    if not pfn:
                        continue
                    flags = _prefetch(kf, [pfn * _ENTRY])[0]
                    if flags is None:
                        continue
                    if flags & _KPF_IDLE and not flags & _KPF_REFERENCED:
                        cold += 1
                    else:
                        hot += 1
        except OSError:
            self.pagemap_ok = False
            self.hot_mb, self.cold_mb = resident, 0.0
            return self.hot_mb, self.cold_mb, 0

        total = hot + cold
        self.samples += 1
        self.probes += total
        if not total:
            self.hot_mb, self.cold_mb = resident, 0.0
            return self.hot_mb, self.cold_mb, 0
        self.hot_frac = hot / total
        self.hot_mb = resident * self.hot_frac
        self.cold_mb = resident - self.hot_mb
        return self.hot_mb, self.cold_mb, total

    @staticmethod
    def _resident(pid, vmas, page_kb):
        try:
            with open(f"/proc/{pid}/statm", encoding="utf-8") as fh:
                return int(fh.read().split()[1]) * page_kb / 1024.0
        except (OSError, IndexError, ValueError):
            span = sum(end - start for start, end in vmas)
            return span / 1024.0 / 1024.0

    def floor_for(self, hot_mb):
        """memory.min for the hot cgroup: the hot side, within a sane band."""
        low = config.HOT_MEM_FLOOR
        high = 2 * 1024 * 1024 * 1024
        want = int(hot_mb * 1024 * 1024)
        return max(low, min(want, high))

    def summary(self):
        return {
            "available": self.available(),
            "hot_mb": round(self.hot_mb, 1),
            "cold_mb": round(self.cold_mb, 1),
            "hot_fraction": round(self.hot_frac, 3),
            "samples": self.samples,
            "probes": self.probes,
        }
