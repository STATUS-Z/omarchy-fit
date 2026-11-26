# omarchy-fit

A workload fit for an Omarchy guest on a small machine. The Linux kernel enforces the parts it actually can: scratch data in RAM, a hot cgroup and a cold cgroup, and a workload record that only shrinks.

It does not replace the syscall table. Sparse routing here means the daemon only arms three kernel controls (tmpfs, cgroup membership, working-set floor). The scheduler polytope is the cgroup boundary: processes outside the hot set stay in the cold set. The memory split is tmpfs plus `memory.min` on the hot cgroup. Tracking is the foreground process and the few programs in its cgroup, not every pair of processes. Speculative preemption is moving a newly foreground program into the hot cgroup before the next sample, and staging `/tmp` so scratch allocations do not hit the disk.

The design space is the set of foreground program names this guest has already shown. K is how many programs the hot set is allowed to hold. Each time the same foreground name repeats, K steps down toward 1. The ceiling is that observed set. Names that never appeared are not invented.

## Absorb

From the guest, as root:

```sh
sudo ./apply.sh
```

That installs the unit, adds the `/tmp` tmpfs line if it is missing, and starts the daemon. Reboot the guest once so `/tmp` is mounted from fstab.
