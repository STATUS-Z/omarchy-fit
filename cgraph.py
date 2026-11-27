"""Sparse inter-process tracking.

The kernel already tells us who ran after whom.  What does not scale is keeping
every pair.  Each process keeps at most K_NEIGHBOURS partners, evicting the
least coupled one when a new partner arrives, so memory is O(K * n) and the
update is O(K) per switch instead of O(n) or O(n^2).
"""

from __future__ import annotations

import config


class Coupling:
    def __init__(self, k=config.K_NEIGHBOURS):
        self.k = k
        self.edges = {}
        self.switches = 0

    def switch(self, prev, nxt):
        if prev <= 0 or nxt <= 0 or prev == nxt:
            return
        self.switches += 1
        self._bump(prev, nxt)
        self._bump(nxt, prev)

    def _bump(self, a, b):
        row = self.edges.get(a)
        if row is None:
            row = self.edges[a] = {}
        row[b] = row.get(b, 0) + 1
        if len(row) > self.k:
            weakest = min(row, key=row.get)
            del row[weakest]

    def partners(self, pid):
        row = self.edges.get(pid) or {}
        return sorted(row.items(), key=lambda kv: (-kv[1], kv[0]))

    def forget(self, live):
        """Drop rows for processes that exited so the table cannot grow."""
        live = set(live)
        for pid in [p for p in self.edges if p not in live]:
            del self.edges[pid]

    def density(self):
        n = max(1, len(self.edges))
        tracked = sum(len(row) for row in self.edges.values())
        return tracked / n, tracked

    def export(self, pids):
        return {p: self.partners(p)[: self.k] for p in pids if p in self.edges}
