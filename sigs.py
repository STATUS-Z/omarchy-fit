"""Syscall signatures, n-gram prediction, and subsystem attribution.

The tracepoint gives syscall numbers, not syscall cost.  To say how many
subsystems a call activates we attribute it from a static table and report the
measured mix per workload class.  The n-gram is what speculation runs on.

The table is a path attribution, not a guess about the syscall table: each
entry lists the kernel subsystems the implementation must pass through.  `read`
on a file touches VFS, the page cache, and the LSM hooks; `futex` touches the
scheduler, the futex hash, and the task's credentials.  Every mapped call lands
on two or three of them, which is the width the sparse router reports.
"""

from __future__ import annotations

from collections import Counter, deque

import config

# x86_64 syscall -> subsystems the implementation runs through.
# Only entries we actually see are needed; unknown numbers report as "unmapped".
SUBSYSTEMS = {
    0: ("fs", "mm", "security"),        # read
    1: ("fs", "mm", "security"),        # write
    2: ("fs", "task", "security"),      # open
    3: ("fs", "mm"),                    # close
    4: ("fs", "task", "security"),      # stat
    5: ("fs", "mm"),                    # fstat
    6: ("fs", "task"),                  # lstat
    7: ("sched", "fs", "time"),         # poll
    8: ("fs", "task"),                  # lseek
    9: ("mm", "fs", "security"),        # mmap
    10: ("mm", "security"),             # mprotect
    11: ("mm", "task"),                 # munmap
    12: ("mm", "task"),                 # brk
    13: ("signal", "task", "security"), # rt_sigaction
    14: ("signal", "task"),             # rt_sigprocmask
    16: ("fs", "task", "security"),     # ioctl
    17: ("fs", "mm", "security"),       # pread64
    18: ("fs", "mm", "security"),       # pwrite64
    19: ("fs", "mm"),                   # readv
    20: ("fs", "mm"),                   # writev
    21: ("fs", "task", "security"),     # access
    22: ("fs", "task"),                 # pipe
    23: ("sched", "fs", "time"),        # select
    24: ("sched", "task"),              # sched_yield
    25: ("mm", "fs"),                   # mremap
    28: ("mm", "fs"),                   # madvise
    32: ("fs", "task"),                 # dup
    33: ("fs", "task"),                 # dup2
    35: ("sched", "time"),              # nanosleep
    39: ("task", "security"),           # getpid
    41: ("net", "fs", "security"),      # socket
    42: ("net", "task", "security"),    # connect
    43: ("net", "sched", "task"),       # accept
    44: ("net", "mm", "security"),      # sendto
    45: ("net", "mm", "security"),      # recvfrom
    46: ("net", "mm", "security"),      # sendmsg
    47: ("net", "mm", "security"),      # recvmsg
    49: ("net", "task", "security"),    # bind
    50: ("net", "task"),                # listen
    54: ("net", "task", "security"),    # setsockopt
    55: ("net", "task", "security"),    # getsockopt
    59: ("task", "mm", "fs"),           # execve
    60: ("task", "mm", "sched"),        # exit
    61: ("task", "sched"),              # wait4
    62: ("signal", "task", "security"), # kill
    63: ("task", "security"),           # uname
    72: ("fs", "task", "security"),     # fcntl
    78: ("fs", "mm"),                   # getdents
    79: ("fs", "task"),                 # getcwd
    80: ("fs", "task", "security"),     # chdir
    82: ("fs", "security"),             # rename
    87: ("fs", "security"),             # unlink
    89: ("fs", "mm"),                   # readlink
    102: ("task", "security"),          # getuid
    104: ("task", "security"),          # getgid
    107: ("task", "security"),          # geteuid
    108: ("task", "security"),          # getegid
    131: ("signal", "mm", "task"),      # sigaltstack
    157: ("task", "security"),          # prctl
    158: ("mm", "task"),                # arch_prctl
    186: ("task", "security"),          # gettid
    202: ("sched", "ipc", "task"),      # futex
    217: ("fs", "mm"),                  # getdents64
    218: ("task", "mm"),                # set_tid_address
    228: ("time", "task"),              # clock_gettime
    230: ("time", "sched"),             # clock_nanosleep
    231: ("task", "mm", "sched"),       # exit_group
    232: ("sched", "fs", "time"),       # epoll_wait
    233: ("fs", "ipc"),                 # epoll_ctl
    257: ("fs", "task", "security"),    # openat
    258: ("fs", "security"),            # mkdirat
    262: ("fs", "mm", "security"),      # newfstatat
    267: ("fs", "mm"),                  # readlinkat
    269: ("fs", "task", "security"),    # faccessat
    270: ("sched", "fs", "time"),       # pselect6
    271: ("sched", "fs", "time"),       # ppoll
    273: ("task", "ipc"),               # set_robust_list
    281: ("sched", "fs", "time"),       # epoll_pwait
    288: ("net", "sched", "task"),      # accept4
    291: ("sched", "fs", "time"),       # epoll_pwait2
    293: ("fs", "task"),                # pipe2
    302: ("task", "security"),          # prlimit64
    318: ("task", "security"),          # getrandom
    332: ("fs", "mm", "security"),      # statx
    334: ("task", "mm"),                # rseq
}


def subsystems(nr):
    return SUBSYSTEMS.get(nr, ("unmapped",))


def width(nr):
    return len(subsystems(nr))


def widths():
    return {nr: len(names) for nr, names in SUBSYSTEMS.items()}


class Predictor:
    """Order-N n-gram over syscall numbers, per workload class."""

    def __init__(self, order=config.ORDER, lookahead=config.LOOKAHEAD):
        self.order = order
        self.lookahead = lookahead
        self.tables = {}          # class -> {tuple -> Counter}
        self.pending = {}         # class -> deque of recent numbers
        self.hits = 0
        self.tries = 0

    def observe(self, cls, nr):
        """Record one syscall for a class and return predicted next numbers."""
        table = self.tables.setdefault(cls, {})
        ctx = self.pending.setdefault(cls, deque(maxlen=self.order))
        if len(ctx) == self.order:
            table.setdefault(tuple(ctx), Counter())[nr] += 1
        ctx.append(nr)
        guess = table.get(tuple(ctx))
        return [n for n, _ in guess.most_common(self.lookahead)] if guess else []

    def score(self, predicted, actual):
        if predicted:
            self.tries += 1
            if actual in predicted:
                self.hits += 1

    def hit_rate(self):
        return (self.hits / self.tries) if self.tries else 0.0

    def size(self):
        return sum(len(t) for t in self.tables.values())


class Mix:
    """Per-class syscall histogram and the shape that names the class.

    The signature is the pair of subsystems that dominate the mix, not a list of
    raw syscall numbers.  Raw numbers churn as a process warms up, which would
    mint a new class — and a new cgroup — on every shift.  Subsystem pairs are
    stable and bounded by how many pairs exist, so the ceiling is finite and
    every entry in it was observed.
    """

    def __init__(self):
        self.counts = Counter()
        self.total = 0
        self.subsystems = Counter()

    def add(self, nr):
        self.counts[nr] += 1
        self.total += 1
        for name in subsystems(nr):
            self.subsystems[name] += 1

    def key(self):
        """Workload identity: the two subsystems this mix is dominated by."""
        if not self.total:
            return "empty"
        top = [name for name, _ in self.subsystems.most_common(2)]
        while len(top) < 2:
            top.append("none")
        return "-".join(top)

    def top_call(self):
        if not self.counts:
            return None
        return self.counts.most_common(1)[0][0]

    def per_call(self):
        """Average subsystems activated per syscall in this class."""
        if not self.total:
            return 0.0
        return sum(self.subsystems.values()) / self.total
