"""Constrained scheduling polytope.

The feasible region is the simplex

    P = { w in R^n : w_i >= 0, sum(w_i) <= BUDGET },  BUDGET=0.95 of capacity.

A point on the interior of that simplex has every admitted class at w_i >= the
simplex's inscribed ball radius, so no admitted class is starved: the region
has no face at w_i = 0 that a running process can be pinned against.  A class
that cannot be admitted is not pushed to w_i = 0 either; it keeps COLD_WEIGHT,
which is the liveness floor, so it still makes progress and cannot livelock.

The scheduler itself is unpatched.  What the kernel enforces is `cpu.weight`:
EEVDF turns weight into a share proportional to w_i / sum(w), so writing the
simplex projection into cgroup weights is the polytope, expressed in the only
scheduling control a cgroup exposes.  Projection is a single scale operation
O(n), not a search.
"""

from __future__ import annotations

import config


class Polytope:
    def __init__(self, budget=config.POLYTOPE_BUDGET):
        self.budget = budget
        self.last = {}

    def project(self, demand):
        """Map class -> demand onto the simplex and return class -> weight.

        demand values are non-negative shares of measured CPU time.  The result
        never sums above `budget`, and every admitted class keeps the share its
        demand earned; if total demand exceeds the budget everything scales by
        the same factor, which preserves the ordering (proportional fairness).
        """
        positive = {k: v for k, v in demand.items() if v > 0}
        total = sum(positive.values())
        if not positive or total <= 0:
            self.last = {}
            return {}
        scale = self.budget / total if total > self.budget else 1.0
        self.last = {k: v * scale for k, v in positive.items()}
        return self.last

    def weights(self, demand):
        """Simplex point -> cgroup cpu.weight integers.

        Weights are an integer range, so the mapping is affine onto
        [COLD_WEIGHT, HOT_WEIGHT]; monotone, so the ordering survives.
        """
        point = self.project(demand)
        if not point:
            return {}
        top = max(point.values())
        span = config.HOT_WEIGHT - config.COLD_WEIGHT
        return {
            k: int(round(config.COLD_WEIGHT + span * (v / top)))
            for k, v in point.items()
        }

    def utilisation(self, demand):
        total = sum(v for v in demand.values() if v > 0)
        return total / self.budget if self.budget else 0.0
