#!/usr/bin/env python3
"""Omarchy fit daemon.

One kernel feed, one decision per tick, one write per control that changed.

    trfeed    -> sched_switch edges and sys_enter numbers, tracked pids only
    cgraph    -> at most K_NEIGHBOURS partners per process
    sigs      -> class signature, subsystem mix, order-2 prediction
    taxonomy  -> discovered classes, K(pi) decreasing, ceiling = observed data
    polytope  -> class demand projected onto the simplex, written as cpu.weight
    hierarchy -> hot facts vs cold inference, from pagemap + kpageflags
    prestage  -> MADV_WILLNEED and dentry warm-up for the predicted calls

A module that cannot reach its kernel interface is skipped and reported in the
model file; the daemon does not invent numbers for it.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time

import cgraph
import config
import hierarchy
import polytope
import prestage
import sigs
import taxonomy
import trfeed


class Fit:
    def __init__(self):
        self.graph = cgraph.Coupling()
        self.space = taxonomy.DesignSpace()
        self.poly = polytope.Polytope()
        self.hier = hierarchy.Hierarchy()
        self.prestage = prestage.Prestage()
        self.predictor = sigs.Predictor()
        self.mixes = {}            # pid -> sigs.Mix
        self.class_of = {}         # pid -> class signature
        self.observed_at = {}      # pid -> mix.total at last observation
        self.cgroup_of = {}        # class signature -> cgroup directory name
        self.written = {}          # control path -> last value written
        self.usage_last = {}       # cgroup -> (monotonic, usage_usec)
        self.trace = trfeed.Trace(self.on_switch, self.on_syscall)
        self.feed_ok = False
        self.ticks = 0
        self.foreground = None
        self.last_pred = {}        # pid -> tuple of predicted numbers
        self.want_warm = {}        # pid -> (class, predicted tuple)
        self.page_kb = self._page_kb()

    @staticmethod
    def _page_kb():
        try:
            return os.sysconf("SC_PAGE_SIZE") // 1024
        except (ValueError, OSError):
            return 4

    # ---- kernel callbacks -------------------------------------------------

    def on_switch(self, prev, nxt):
        self.graph.switch(prev, nxt)

    def on_syscall(self, pid, nr):
        mix = self.mixes.get(pid)
        if mix is None:
            mix = self.mixes[pid] = sigs.Mix()
        mix.add(nr)

        # Score the guess made on the previous call before replacing it.
        guess = self.last_pred.get(pid)
        if guess is not None:
            self.predictor.score(guess, nr)

        cls = self.class_of.get(pid)
        if cls is None:
            return
        predicted = self.predictor.observe(cls, nr)
        self.last_pred[pid] = tuple(predicted)
        if predicted and predicted != guess:
            # This runs on the trace reader thread.  Queue the work and let the
            # tick loop do the I/O, so a slow filesystem cannot stall the pipe.
            self.want_warm[pid] = (cls, tuple(predicted))

    def drain_warm(self):
        """Issue the pre-staging queued by the trace thread, foreground only."""
        if not self.want_warm:
            return 0
        pid = self.foreground
        item = self.want_warm.pop(pid, None) if pid else None
        if len(self.want_warm) > 64:          # bounded queue; drop stale entries
            self.want_warm.clear()
        if item is None:
            return 0
        cls, predicted = item
        return self.prestage.warm(cls, predicted, pid)

    # ---- observation ------------------------------------------------------

    @staticmethod
    def foreground_pid():
        try:
            raw = subprocess.check_output(
                ["hyprctl", "activewindow", "-j"], text=True, timeout=2
            )
            data = json.loads(raw)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return None
        try:
            pid = int(data.get("pid") or 0)
        except (TypeError, ValueError):
            return None
        return pid if pid > 0 else None

    @staticmethod
    def proc_name(pid):
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as fh:
                return fh.read().strip()
        except OSError:
            return None

    @staticmethod
    def maps(pid):
        rows = []
        try:
            with open(f"/proc/{pid}/maps", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 2 or "r" not in parts[1]:
                        continue
                    try:
                        start, end = (int(x, 16) for x in parts[0].split("-"))
                    except ValueError:
                        continue
                    rows.append((start, end))
        except OSError:
            return rows
        return rows

    @staticmethod
    def open_files(pid):
        out = []
        base = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(base):
                try:
                    target = os.readlink(f"{base}/{fd}")
                except OSError:
                    continue
                if target.startswith("/") and " (deleted)" not in target:
                    out.append(target)
        except OSError:
            return out
        return out

    @staticmethod
    def cgroup_usage():
        """Cumulative CPU time per class cgroup, in microseconds."""
        out = {}
        try:
            entries = os.listdir(config.CG_ROOT)
        except OSError:
            return out
        for name in entries:
            try:
                with open(f"{config.CG_ROOT}/{name}/cpu.stat", encoding="utf-8") as fh:
                    for line in fh:
                        if line.startswith("usage_usec"):
                            out[name] = int(line.split()[1])
                            break
            except (OSError, IndexError, ValueError):
                continue
        return out

    def demand(self):
        """CPU rate per admitted class, in seconds of CPU per second of wall."""
        now = time.monotonic()
        usage = self.cgroup_usage()
        rate = {}
        for group, usec in usage.items():
            last = self.usage_last.get(group)
            if last is not None:
                dt = max(1e-6, now - last[0])
                delta = max(0, usec - last[1])
                rate[group] = (delta / 1e6) / dt
        self.usage_last = {g: (now, u) for g, u in usage.items()}
        return rate

    # ---- control ----------------------------------------------------------

    def cgroup_for(self, signature):
        name = self.cgroup_of.get(signature)
        if name:
            return name
        digest = hashlib.sha1(signature.encode("utf-8")).hexdigest()[:12]
        name = f"c-{digest}"
        self.cgroup_of[signature] = name
        path = f"{config.CG_ROOT}/{name}"
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            return None
        return name

    def write_value(self, path, value):
        """Write a control that holds state; skip if already at that value."""
        if self.written.get(path) == value:
            return False
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(str(value))
        except OSError:
            return False
        self.written[path] = value
        return True

    def move(self, pid, cgroup):
        """Membership is an action, not state, so it is always written."""
        try:
            with open(f"{config.CG_ROOT}/{cgroup}/cgroup.procs", "w",
                      encoding="utf-8") as fh:
                fh.write(str(pid))
        except OSError:
            return False
        return True

    def setup(self):
        try:
            os.makedirs(config.STATE, exist_ok=True)
        except OSError:
            pass
        try:
            os.makedirs(config.CG_ROOT, exist_ok=True)
        except OSError:
            return False
        self.write_value(f"{config.CG_ROOT}/cgroup.subtree_control", "+cpu +memory")
        return True

    @staticmethod
    def live_pids():
        live = {}
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            name = Fit.proc_name(pid)
            if name:
                live[pid] = name
        return live

    # ---- the loop ---------------------------------------------------------

    def tick(self):
        self.ticks += 1
        now = time.time()
        live = self.live_pids()
        self.graph.forget(live)
        for pid in [p for p in self.mixes if p not in live]:
            del self.mixes[pid]
            self.class_of.pop(pid, None)
            self.observed_at.pop(pid, None)
            self.last_pred.pop(pid, None)

        pid = self.foreground_pid()
        self.foreground = pid
        name = self.proc_name(pid) if pid else None
        if not pid:
            return

        mix = self.mixes.setdefault(pid, sigs.Mix())
        signature = mix.key()
        seen_at = self.observed_at.get(pid, 0)
        if mix.total - seen_at >= config.EVENT_WINDOW:
            # Decay is tied to observed work, not to how long the daemon ran.
            self.observed_at[pid] = mix.total
            self.space.observe(signature, now)
            self.class_of[pid] = signature
            group = self.cgroup_for(signature)
            if group:
                for path in self.open_files(pid)[:8]:
                    self.prestage.remember_open(signature, path)
        else:
            group = self.cgroup_of.get(signature)

        if group:
            # Membership is an action, not stored state: write it every tick so
            # a newly focused process is admitted without waiting a full window.
            self.move(pid, group)

        usage = self.demand()
        admitted = self.space.admitted()
        demand = {}
        for sig in admitted:
            group_name = self.cgroup_of.get(sig)
            if not group_name:
                continue
            # A class that has just been admitted has no measured rate yet. Give
            # it an equal share rather than zero, so admission actually means a
            # share of the simplex on the very first tick.
            demand[group_name] = usage.get(group_name, 0.0) or 1.0 / len(admitted)
        weights = self.poly.weights(demand)
        for group_name, weight in weights.items():
            self.write_value(f"{config.CG_ROOT}/{group_name}/cpu.weight", weight)
        for group_name in self.cgroup_of.values():
            if group_name not in weights:
                self.write_value(f"{config.CG_ROOT}/{group_name}/cpu.weight",
                                 config.COLD_WEIGHT)
                self.write_value(f"{config.CG_ROOT}/{group_name}/memory.min", 0)

        rows = self.maps(pid) if pid else []
        page_kb = max(1, self.page_kb)
        hot_mb, cold_mb, probes = self.hier.split(pid, rows, page_kb)
        if group and signature in admitted:
            # Only an admitted class gets a resident floor. A cold class keeps
            # memory.min 0 so the kernel may reclaim it first.
            self.write_value(f"{config.CG_ROOT}/{group}/memory.min",
                             self.hier.floor_for(hot_mb))

        self.drain_warm()
        self.trace.set_pids(
            [pid] + [p for p, _ in self.graph.partners(pid)][: config.K_NEIGHBOURS]
            if pid else []
        )
        self.save(name, signature, hot_mb, cold_mb, probes)

    def save(self, name, signature, hot_mb, cold_mb, probes):
        density, edges = self.graph.density()
        model = {
            "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "ticks": self.ticks,
            "foreground": name,
            "foreground_class": signature,
            "k_pi": self.space.k_pi(),
            "classes": {
                sig: {
                    "count": c.count,
                    "last_seen": time.strftime(
                        "%Y-%m-%dT%H:%M:%S", time.localtime(c.last_seen)
                    ),
                    "cgroup": self.cgroup_of.get(sig),
                    "admitted": sig in admitted,
                }
                for sig, c in self.space.classes.items()
            },
            "ceiling": self.space.ceiling(),
            "counters": {
                "switches": self.graph.switches,
                "coupling_density": round(density, 3),
                "coupling_edges": edges,
                "predict_hit_rate": round(self.predictor.hit_rate(), 4),
                "predict_tables": self.predictor.size(),
                "prestage": self.prestage.summary(),
                "memory": self.hier.summary(),
                "memory_probes": probes,
                "hot_mb": round(hot_mb, 1),
                "cold_mb": round(cold_mb, 1),
            },
            "feed": self.feed_ok,
        }
        try:
            tmp = config.MODEL + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(model, fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.replace(tmp, config.MODEL)
        except OSError:
            pass

    def run(self):
        ready = self.setup()
        if ready:
            self.feed_ok = self.trace.start()
        while True:
            try:
                self.tick()
            except Exception:     # keep the unit alive; ticks keep counting
                pass
            time.sleep(config.TICK)


def main():
    Fit().run()


if __name__ == "__main__":
    main()
