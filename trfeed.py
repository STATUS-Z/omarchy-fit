"""Kernel tracepoint feed, restricted to the processes the fit tracks.

One trace_pipe.  /sys/kernel/tracing/set_event_pid is narrowed to the tracked
set, so the kernel emits nothing for the rest of the machine.  Two consumers:
sched_switch pairs feed the sparse coupling graph, sys_enter ids feed the
signature that the taxonomy classifies and the predictor pre-stages.
"""

from __future__ import annotations

import re
import threading

TRACE = "/sys/kernel/tracing"
EVENTS = ("sched/sched_switch", "raw_syscalls/sys_enter")

_LINE = re.compile(
    r"^\s*(?P<comm>.+)-(?P<pid>\d+)\s+\[\d+\]\s+\S+\s+"
    r"(?P<ts>[\d.]+):\s+(?P<event>\w+):\s*(?P<rest>.*)$"
)
_PREV = re.compile(r"prev_pid=(\d+)")
_NEXT = re.compile(r"next_pid=(\d+)")
_NR = re.compile(r"NR (\d+)")


def write(path, value):
    try:
        with open(path, "w") as fh:
            fh.write(str(value))
        return True
    except OSError:
        return False


class Trace:
    def __init__(self, on_switch, on_syscall):
        self.on_switch = on_switch
        self.on_syscall = on_syscall
        self.pids = ()
        self._stop = False
        self._fh = None
        self._thread = None
        self.ok = False

    def start(self):
        for event in EVENTS:
            write(f"{TRACE}/events/{event}/enable", 1)
        write(f"{TRACE}/tracing_on", 1)
        try:
            self._fh = open(f"{TRACE}/trace_pipe", "r", errors="replace")
        except OSError:
            self.ok = False
            return False
        self.ok = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return True

    def set_pids(self, pids):
        wanted = tuple(sorted({int(p) for p in pids if int(p) > 0}))
        if wanted == self.pids:
            return
        self.pids = wanted
        write(f"{TRACE}/set_event_pid", 0)
        if wanted:
            write(f"{TRACE}/set_event_pid", " ".join(str(p) for p in wanted))

    def _run(self):
        for line in self._fh:
            if self._stop:
                break
            m = _LINE.match(line)
            if not m:
                continue
            rest = m.group("rest")
            event = m.group("event")
            try:
                if event == "sched_switch":
                    prev = _PREV.search(rest)
                    nxt = _NEXT.search(rest)
                    if prev and nxt:
                        self.on_switch(int(prev.group(1)), int(nxt.group(1)))
                elif event == "sys_enter":
                    nr = _NR.search(rest)
                    if nr:
                        self.on_syscall(int(m.group("pid")), int(nr.group(1)))
            except (ValueError, RuntimeError):
                continue

    def stop(self):
        self._stop = True
        write(f"{TRACE}/set_event_pid", 0)
        for event in EVENTS:
            write(f"{TRACE}/events/{event}/enable", 0)
