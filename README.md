# omarchy-fit

The five properties, expressed in controls this machine already enforces, plus
the `/tmp` tmpfs, plus the update where the system designs itself. Nothing here
patches the Linux kernel, and nothing here is labelled as if it did.

```
1. Sparse syscall routing — each syscall activates only 2–3 kernel subsystems
   instead of the full dispatch path = ~10× reduction in per-syscall overhead
2. Constrained scheduling polytope — restrict the scheduler's feasible region to
   a geometric object that provably eliminates starvation and livelock while
   maximizing throughput = Training-stability analog: the system can't collapse
   under adversarial workloads
3. Conditional memory hierarchy — split working set into "hot facts" (in-cache
   page tables, O(1)) and "cold inference" (page fault resolution, O(log n)) with
   an inferred access pattern that makes the split optimal = 90%+ reduction in
   page-fault latency for common workloads
4. Sparse inter-process tracking — instead of O(n²) interference monitoring
   across all running processes, track only the k most-coupled neighbors = Scales
   to 10⁶ processes without quadratic overhead
5. Speculative preemption — predict the next 3–5 syscalls a process will make and
   pre-stage resources = Hides latency, improves throughput

An OS that achieves near-optimal resource allocation under any workload in its
design space, with O(1) or O(log n) per-operation overhead, by finding the right
structural constraints on its decision space.

The update is: the system becomes its own designer:

1. Design space = discovered workload taxonomy (the system finds new workload
   classes it wasn't told about)
2. K(π) decreasing over time
3. Ceiling = data (the actual distribution of workloads that exist); all in one
   package; the true version.
```

## The tmp config

`/tmp` is tmpfs, so scratch data never reaches the virtual disk:

```
tmpfs /tmp tmpfs rw,nosuid,nodev,noatime,size=1G,mode=1777 0 0
```

`apply.sh` appends that line behind a `# omarchy-fit tmpfs` tag if it is absent
and mounts it immediately if `/tmp` is still on the root filesystem. One guest
reboot makes fstab the authority.

## How each property is carried

Every line below names the kernel mechanism that does the work. The daemon
configures those mechanisms; it does not reimplement them.

| Property | Mechanism in this fit | What the kernel enforces |
|---|---|---|
| 1. Sparse syscall routing | `trfeed.py` narrows the tracepoint feed with `set_event_pid`; `sigs.py` attributes each syscall to a 2–3 subsystem path and reports the measured mix per class; `verify.py` proves every mapped call is 2–3 wide | `set_event_pid` — the kernel emits events only for tracked pids, so observation cost is paid over the tracked set instead of the process tree |
| 2. Constrained scheduling polytope | `polytope.py` projects class demand onto the simplex `{w ≥ 0, Σw ≤ 0.95}` and writes the projection as `cpu.weight` | cgroup v2 `cpu.weight`, consumed by EEVDF at every scheduling decision |
| 3. Conditional memory hierarchy | `hierarchy.py` probes one page per mapping, reads `/proc/<pid>/pagemap` then `/proc/kpageflags`, and splits resident memory into referenced (hot facts) and idle (cold inference) | `pagemap` + `kpageflags` for the access pattern, `memory.min` on the hot cgroup for the guarantee |
| 4. Sparse inter-process tracking | `cgraph.py` keeps at most 8 coupled partners per process, evicting the weakest on overflow | `sched_switch` tracepoint supplies the edges; the bound is `K_NEIGHBOURS` |
| 5. Speculative preemption | `sigs.py` predicts the next 4 syscalls from an order-2 n-gram per class; `prestage.py` warms the files the class opened and `MADV_WILLNEED`s the largest mappings | `madvise(MADV_WILLNEED)` and page-cache warm-up before the call arrives |

`fitd.py` binds them: one kernel feed, one decision per tick, one write per
changed control. `taxonomy.py` is the designer — the set of classes is read out
of the observed syscall mixes, `K(π)` only decreases, and the ceiling is the
sorted list of classes that actually ran.

## Modules

| File | Role |
|---|---|
| `config.py` | Every structural constant in one place: simplex budget, K bounds, probe caps |
| `trfeed.py` | One `trace_pipe` reader, pid-filtered by the kernel |
| `sigs.py` | Syscall → subsystem table, per-class mix, order-2 predictor |
| `cgraph.py` | K-bounded coupling graph over `sched_switch` edges |
| `taxonomy.py` | Discovered classes, `K(π)`, ceiling |
| `polytope.py` | Simplex projection and weight mapping |
| `hierarchy.py` | Hot/cold split from `pagemap` + `kpageflags` |
| `prestage.py` | Dentries and `MADV_WILLNEED` for predicted calls |
| `fitd.py` | The loop that binds all of the above |
| `verify.py` | Module self-check; exits non-zero if a property fails |

`verify.py` is the claim checker. It runs under plain `python3`, touches no
kernel interface, and asserts the structural properties: every mapped syscall
is 2–3 subsystems wide, the projection stays inside the simplex and preserves
ordering, partner count never exceeds K, `K(π)` is monotone non-increasing,
the ceiling contains no name that was not observed, the memory split conserves
resident bytes, and the predictor learns a repeating loop.

## Absorb

From the guest, as root:

```sh
sudo ./apply.sh
```

That installs the modules to `/usr/local/lib/omarchy-fit/`, the unit to
`/etc/systemd/system/omarchy-fit.service`, ensures the tmpfs line, and enables
the service. Reboot the guest once so `/tmp` is mounted from fstab.

## Reading the model

`/var/lib/omarchy-fit/model.json` holds what was measured and nothing else:

- `classes` — each discovered signature with `count`, `last_seen`, and its cgroup
- `k_pi` — current admission width, which only falls
- `ceiling` — the sorted class list, i.e. the observed workload distribution
- `counters` — switches, coupling density, predictor hit rate, memory split,
  pre-stage totals
- `feed` — whether the tracepoint feed attached; `false` means the daemon is
  running with no syscall visibility and the model says so

A signature is the pair of subsystems a class is dominated by (`fs-mm`,
`net-sched`, …), so the number of possible classes is bounded and every class
that exists in the file was observed on this machine.

## What this is not

It is not a patched kernel and it does not claim the measured speedups in the
five properties. Those numbers describe an OS whose syscall dispatcher, EEVDF
region, and fault path are built that way. This repo is the largest honest
subset that a stock Linux kernel exposes to a userspace daemon: the property in
each row above is carried by the mechanism named in the last column, and
`verify.py` checks the structure — not a benchmark.

Read `counters` after a day of real use to see what the machine actually did.
