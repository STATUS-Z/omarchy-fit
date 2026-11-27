#!/usr/bin/env python3
"""Self-check for the fit's module math.

Runs with plain python3, touches no kernel interface, and exits non-zero on the
first property that does not hold. This is what says the modules do what the
README says, instead of asking the reader to trust the prose.
"""

from __future__ import annotations

import sys

import cgraph
import config
import hierarchy
import polytope
import sigs
import taxonomy

failures = []


def check(label, ok, detail=""):
    if ok:
        print(f"  ok   {label}{(' — ' + detail) if detail else ''}")
    else:
        failures.append(label)
        print(f"  FAIL {label}{(' — ' + detail) if detail else ''}")


def routing():
    """Every mapped syscall resolves to 2 or 3 subsystems."""
    table = sigs.widths()
    narrow = [nr for nr, w in table.items() if w < 2]
    wide = [nr for nr, w in table.items() if w > 3]
    check("every mapped syscall is 2..3 subsystems wide",
          not narrow and not wide,
          f"mapped={len(table)} min={min(table.values())} max={max(table.values())}"
          + (f" under={narrow[:4]}" if narrow else "")
          + (f" over={wide[:4]}" if wide else ""))
    unknown = sigs.subsystems(999999)
    check("unknown syscall reports unmapped", unknown == ("unmapped",), str(unknown))
    mix = sigs.Mix()
    for nr in (257, 0, 0, 1, 231):
        mix.add(nr)
    check("measured mix stays in the 2..3 band", 2.0 <= mix.per_call() <= 3.0,
          f"per_call={mix.per_call():.2f}")


def polytope_property():
    """Projection stays inside the simplex and preserves ordering."""
    poly = polytope.Polytope()
    demand = {"a": 5.0, "b": 3.0, "c": 1.0}
    point = poly.project(demand)
    total = sum(point.values())
    check("projection inside the simplex", total <= config.POLYTOPE_BUDGET + 1e-9,
          f"sum={total:.4f} budget={config.POLYTOPE_BUDGET}")
    check("projection preserves order",
          point["a"] > point["b"] > point["c"],
          f"{point}")
    weights = poly.weights(demand)
    check("weights are integers in range",
          all(isinstance(v, int) and config.COLD_WEIGHT <= v <= config.HOT_WEIGHT
              for v in weights.values()),
          f"{weights}")
    zero = poly.weights({"a": 0.0})
    check("no demand means no admitted weight", zero == {}, str(zero))
    many = {f"p{i}": 1.0 for i in range(200)}
    point = poly.project(many)
    check("200 classes still bounded",
          sum(point.values()) <= config.POLYTOPE_BUDGET + 1e-9,
          f"sum={sum(point.values()):.4f}")


def tracking_property():
    """Edges per process never exceed K, and rows are reclaimable."""
    graph = cgraph.Coupling(k=4)
    for i in range(1, 200):
        graph.switch(1, i)
    row = graph.edges[1]
    check("partner count bounded by K", len(row) <= 4, f"len={len(row)}")
    density, edges = graph.density()
    check("density does not grow with n", edges <= 4 * len(graph.edges),
          f"edges={edges} rows={len(graph.edges)}")
    graph.forget([2])
    check("forget drops exited pids", 1 not in graph.edges,
          f"rows={len(graph.edges)}")


def taxonomy_property():
    """K(pi) decreases and never rises; the ceiling holds only observed names."""
    space = taxonomy.DesignSpace()
    seen = []
    for i in range(60):
        name = "sig-a" if i % 2 else "sig-b"
        seen.append(name)
        space.observe(name, now=float(i))
    first = taxonomy.DesignSpace()
    first.observe("only", now=0.0)
    k_start = first.k_pi()
    check("K(pi) starts at K_START", k_start == config.K_START, f"k={k_start}")
    check("K(pi) decreases with observation", space.k_pi() < k_start,
          f"{k_start} -> {space.k_pi()}")
    check("K(pi) respects the floor", space.k_pi() >= config.K_FLOOR,
          f"floor={config.K_FLOOR}")
    series = []
    probe = taxonomy.DesignSpace()
    for i in range(80):
        probe.observe("sig-a" if i % 3 else "sig-b", now=float(i))
        series.append(probe.k_pi())
    check("K(pi) never rises across 80 observations",
          all(b <= a for a, b in zip(series, series[1:])),
          f"{series[0]} -> {series[-1]} over {len(series)} steps")
    check("K(pi) is strictly decreasing while above the floor",
          series[0] > series[-1] and series[-1] == config.K_FLOOR,
          f"start={series[0]} end={series[-1]} floor={config.K_FLOOR}")
    check("ceiling equals observed signatures",
          set(space.ceiling()) == set(seen), str(space.ceiling()))
    check("unseen class is not in the ceiling", "never-ran" not in space.ceiling(),
          "no invented names")
    check("admitted set is bounded by K(pi)",
          len(space.admitted()) <= space.k_pi(),
          f"admitted={len(space.admitted())} k={space.k_pi()}")
    check("admitted set drawn only from observed classes",
          space.admitted() <= set(space.ceiling()), str(space.admitted()))


def memory_property():
    """The split conserves resident memory and probes one page per mapping."""
    hier = hierarchy.Hierarchy()
    vmas = [(0x1000 * i, 0x1000 * (i + 1)) for i in range(40)]
    hier.pagemap_ok = False
    hot, cold, probes = hier.split(1, vmas, 4)
    check("no pagemap means all resident is hot", cold == 0.0,
          f"hot={hot:.1f} cold={cold:.1f}")
    check("no probes issued without pagemap", probes == 0, f"probes={probes}")
    hier.pagemap_ok = True
    hier.kpage_ok = False
    hot2, cold2, probes2 = hier.split(1, vmas, 4)
    check("unreadable flags fall back to hot", cold2 == 0.0, f"cold={cold2:.1f}")
    check("split conserves rss", abs((hot2 + cold2) - hot) < 1e-6,
          f"{hot2:.1f} + {cold2:.1f}")
    floor = hier.floor_for(512.0)
    check("memory.min floor inside the band",
          config.HOT_MEM_FLOOR <= floor <= 2 * 1024 * 1024 * 1024,
          f"floor={floor}")
    check("probes bounded by VMA_PROBES",
          min(len(vmas), config.VMA_PROBES) >= probes2,
          f"probes={probes2} cap={config.VMA_PROBES}")


def prediction_property():
    """An order-2 table learns a repeating sequence and predicts it."""
    pred = sigs.Predictor()
    seq = [257, 0, 0, 1, 231]
    last = None
    for _ in range(60):
        for nr in seq:
            if last:
                pred.score(last, nr)          # score last call's guess
            last = tuple(pred.observe("cls", nr)) or None
    check("predictor learns a repeating loop", pred.hit_rate() > 0.9,
          f"hit_rate={pred.hit_rate():.3f} tables={pred.size()}")
    check("predictions bounded by lookahead", pred.lookahead == config.LOOKAHEAD,
          f"lookahead={pred.lookahead}")
    check("table stays one class", len(pred.tables) == 1,
          f"classes={list(pred.tables)}")


def main():
    quiet = "--quiet" in sys.argv
    if quiet:
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            routing(); polytope_property(); tracking_property()
            taxonomy_property(); memory_property(); prediction_property()
    else:
        print("sparse syscall routing"); routing()
        print("constrained scheduling polytope"); polytope_property()
        print("sparse inter-process tracking"); tracking_property()
        print("design space and K(pi)"); taxonomy_property()
        print("conditional memory hierarchy"); memory_property()
        print("speculative preemption"); prediction_property()
    if failures:
        print(f"\n{len(failures)} failed: {', '.join(failures)}")
        return 1
    if not quiet:
        print("\nall module checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
