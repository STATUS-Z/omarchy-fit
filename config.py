"""Constants for the Omarchy fit.

Every number here is a structural limit, not a tuning knob that drifts.  The
daemon may only move a workload between the admitted set and the rest; it may
never invent a class it has not observed.
"""

CG_ROOT = "/sys/fs/cgroup/omarchy-fit"
STATE = "/var/lib/omarchy-fit"
MODEL = STATE + "/model.json"

TICK = 1.0                  # seconds between fit decisions
EVENT_WINDOW = 64           # syscalls in one signature before classification

# Scheduling polytope: the admitted set is a simplex on measured utilization.
POLYTOPE_BUDGET = 0.95      # fraction of total CPU capacity the simplex may use
CPU_PERIOD = 100000         # cgroup v2 period, microseconds
HOT_WEIGHT = 10000
COLD_WEIGHT = 100

# Conditional memory hierarchy.
HOT_MEM_FLOOR = 256 * 1024 * 1024
VMA_PROBES = 32             # one page per mapping, not every page

# Sparse inter-process tracking.
K_NEIGHBOURS = 8            # coupled neighbours kept per process, never O(n)
K_START = 4                 # hot-set width before decay
K_FLOOR = 1                 # K(pi) never reaches zero
K_DECAY_EVERY = 10          # observations of one class before K steps down

# Speculative preemption.
ORDER = 2                   # syscall n-gram order
LOOKAHEAD = 4               # syscalls predicted ahead
PRE_STAGE_HINTS = {0, 1, 2, 3, 5, 8, 9, 11, 12, 21, 257, 262}
