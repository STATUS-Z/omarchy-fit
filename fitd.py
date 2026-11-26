#!/usr/bin/env python3
"""Hot/cold cgroup fit. Kernel enforces membership, cpu.weight, and memory.min."""

import json
import os
import subprocess
import time

CG = "/sys/fs/cgroup/omarchy-fit"
MODEL = "/var/lib/omarchy-fit/model"
HOT_NAMES = set()
K_FLOOR = 1


def write(path, text):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(str(text))
        return True
    except OSError:
        return False


def setup():
    os.makedirs(CG + "/hot", exist_ok=True)
    os.makedirs(CG + "/cold", exist_ok=True)
    os.makedirs("/var/lib/omarchy-fit", exist_ok=True)
    write(CG + "/cgroup.subtree_control", "+cpu +memory")
    write(CG + "/hot/cpu.weight", "10000")
    write(CG + "/cold/cpu.weight", "100")
    write(CG + "/hot/memory.min", str(256 * 1024 * 1024))


def foreground_pid():
    try:
        raw = subprocess.check_output(["hyprctl", "activewindow", "-j"], text=True, timeout=2)
        data = json.loads(raw)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
    pid = int(data.get("pid") or 0)
    if pid <= 0:
        return None
    try:
        name = open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace").read().strip()
    except OSError:
        return None
    return pid, name


def load():
    counts = {}
    seen = {}
    if not os.path.exists(MODEL):
        return counts, seen
    for line in open(MODEL, encoding="utf-8"):
        parts = line.split()
        if len(parts) < 3:
            continue
        if parts[0] == "k":
            counts[parts[1]] = int(parts[2])
        elif parts[0] == "seen":
            seen.setdefault(parts[1], set()).add(parts[2])
    return counts, seen


def store(counts, seen):
    lines = []
    for name, n in counts.items():
        lines.append(f"k {name} {n}")
    for name, group in seen.items():
        for item in sorted(group):
            lines.append(f"seen {name} {item}")
    with open(MODEL, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))


def place(pid, dest):
    write(f"{CG}/{dest}/cgroup.procs", str(pid))


def main():
    setup()
    last = None
    while True:
        found = foreground_pid()
        if not found:
            time.sleep(1)
            continue
        pid, name = found
        counts, seen = load()
        known = seen.get("hot", set())
        counts[name] = counts.get(name, 0) + 1
        if name not in known:
            known.add(name)
        # K decreases toward the floor as this name keeps returning.
        k = max(K_FLOOR, 4 - min(3, counts[name] // 10))
        seen["hot"] = set(sorted(known)[:k]) if len(known) > k else known
        store(counts, seen)
        if name in seen["hot"]:
            place(pid, "hot")
        else:
            place(pid, "cold")
        if name != last:
            last = name
        time.sleep(1)


if __name__ == "__main__":
    main()
