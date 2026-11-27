"""The design space: workload classes discovered from the syscall mix.

Nothing is pre-declared. A class exists only after the tracepoint feed has
produced its signature, so the set of classes is an observation, not a guess.
The ceiling is that observed set: the actual distribution of workloads that
exist on this machine.

K(pi) is the policy's admission width — how many classes the scheduler is
allowed to hold at once. It is `K_START` at first and steps down as
observations accumulate, never rising and never reaching zero:

    K(pi) = max(K_FLOOR, K_START - observations // K_DECAY_EVERY)

The admitted set is the K(pi) most recently active classes. Classes outside it
are not dropped; they keep the cold weight, so they still make progress.
"""

from __future__ import annotations

import config


class ClassInfo:
    __slots__ = ("name", "first_seen", "last_seen", "count")

    def __init__(self, name, now):
        self.name = name
        self.first_seen = now
        self.last_seen = now
        self.count = 0


class DesignSpace:
    def __init__(self):
        self.classes = {}
        self.observations = 0

    def observe(self, signature, now):
        info = self.classes.get(signature)
        if info is None:
            info = self.classes[signature] = ClassInfo(signature, now)
        info.count += 1
        info.last_seen = now
        self.observations += 1
        return info

    def k_pi(self):
        """Admission width. Monotone non-increasing in the observation count."""
        return max(
            config.K_FLOOR,
            config.K_START - self.observations // config.K_DECAY_EVERY,
        )

    def admitted(self):
        """The K(pi) most recently active classes."""
        budget = self.k_pi()
        recent = sorted(self.classes.values(), key=lambda c: -c.last_seen)
        return {c.name for c in recent[:budget]}

    def ordered(self):
        return sorted(self.classes.values(), key=lambda c: (-c.count, c.name))

    def ceiling(self):
        """Every class that has actually run, most-observed first."""
        return [c.name for c in self.ordered()]
