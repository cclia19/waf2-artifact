#!/usr/bin/env python3
"""
Analysis of the multi-node consortium measurement.

Input:  harness/consortium_results.json (produced by harness/consortium_bench.py
        against a real N-node go-ethereum v1.13.15 Clique PoA chain)
Output: statistics + IEEE single-column figure.
"""
import json, os
import numpy as np
from scipy import stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
# Prefer a fresh run; fall back to the published results so that a reviewer can
# regenerate Table V and Figure 1 without first spending ~15 minutes running the
# consortium benchmark.
_fresh = os.path.join(HERE, "..", "harness", "consortium_results.json")
_pub = os.path.join(HERE, "..", "results", "consortium_results.json")
_src = _fresh if os.path.exists(_fresh) else _pub
RES = json.load(open(_src))
print(f"source: {'fresh run' if _src == _fresh else 'published results/'} ({_src})")

C = {"prop": "#2166AC", "incl": "#B2182B", "fit": "#D6881A"}
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["DejaVu Serif"],
    "font.size": 8, "axes.labelsize": 8, "legend.fontsize": 7,
    "xtick.labelsize": 7, "ytick.labelsize": 7,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.linewidth": 0.6, "grid.linewidth": 0.4, "grid.alpha": 0.3,
    "lines.linewidth": 1.4, "lines.markersize": 4,
    "figure.dpi": 300, "savefig.dpi": 300, "savefig.bbox": "tight",
})

n = np.array([r["nodes"] for r in RES], float)
pm = np.array([r["propagation"]["median_ms"] for r in RES])
p95 = np.array([r["propagation"]["p95_ms"] for r in RES])
im = np.array([r["inclusion"]["median_ms"] for r in RES])
tm = np.array([r["total"]["median_ms"] for r in RES])
samples = [r["propagation"]["n"] for r in RES]

print("=" * 70)
print("REVOCATION PROPAGATION — real N-node Clique PoA consortium")
print("geth v1.13.15, block period 2 s, 20 revocations per size")
print("=" * 70)
print(f"\n{'n':>3} {'inclusion med':>14} {'propagation med':>16} {'p95':>8} {'total med':>11} {'obs':>5}")
for r in RES:
    print(f"{r['nodes']:>3} {r['inclusion']['median_ms']:>11.0f} ms "
          f"{r['propagation']['median_ms']:>13.1f} ms {r['propagation']['p95_ms']:>5.0f} ms "
          f"{r['total']['median_ms']:>8.0f} ms {r['propagation']['n']:>5}")
print(f"\nTotal per-node propagation observations: {sum(samples)}")

print("\n--- 1. Does propagation scale with consortium size? ---")
for name, X in [("linear in n", n), ("log n", np.log(n)), ("sqrt n", np.sqrt(n))]:
    lr = stats.linregress(X, pm)
    print(f"  {name:<14} R2={lr.rvalue**2:.4f}  slope={lr.slope:.2f}  intercept={lr.intercept:.2f}")
lin = stats.linregress(n, pm)
print(f"\n  Best description over the measured range: "
      f"T_prop(n) = {lin.intercept:.1f} + {lin.slope:.2f}*n ms  (R2={lin.rvalue**2:.4f})")
print(f"  i.e. roughly {lin.slope:.1f} ms of additional propagation delay per access point.")
print("  NOTE: four consortium sizes over 4-13 nodes. We report the slope over")
print("  the measured range and do NOT extrapolate to larger consortia.")

print("\n--- 2. Does block inclusion scale with consortium size? ---")
li = stats.linregress(n, im)
print(f"  inclusion median range {im.min():.0f}-{im.max():.0f} ms, "
      f"slope {li.slope:.1f} ms/node, p={li.pvalue:.3f}")
print(f"  -> {'NO significant dependence' if li.pvalue > 0.05 else 'dependence detected'} on n.")
print(f"  Inclusion is governed by the Clique block period (2 s), a tunable")
print(f"  consensus parameter, not by consortium size.")

print("\n--- 3. Where does the time actually go? ---")
for r in RES:
    tot = r["total"]["median_ms"]; pr = r["propagation"]["median_ms"]
    print(f"  n={r['nodes']:>2}: propagation is {100*pr/tot:4.1f}% of end-to-end "
          f"revocation latency ({pr:.0f} ms of {tot:.0f} ms)")
print("\n  The dominant term is consensus inclusion, not dissemination. Halving")
print("  the block period roughly halves end-to-end revocation latency; adding")
print("  access points barely moves it.")

print("\n--- 4. Security interpretation ---")
worst = max(r["total"]["max_ms"] for r in RES) / 1000
print(f"  Worst observed end-to-end revocation latency across all runs: {worst:.2f} s.")
print(f"  This is the window during which a revoked credential may still be")
print(f"  honoured at a remote access point. It is bounded by consensus")
print(f"  parameters and is orders of magnitude below the credential lifetime")
print(f"  cap (7 days) that bounds the failure mode of a partitioned replica.")

# ------------------------------------------------------------------ figure
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.16, 2.5))

# (a) propagation vs consortium size: median line with a median-to-p95 band
ax1.fill_between(n, pm, p95, color=C["prop"], alpha=0.13, lw=0,
                 label="Median to 95th pct.")
ax1.plot(n, pm, "o-", color=C["prop"], label="Median", zorder=3)
xs = np.linspace(n.min(), n.max(), 100)
ax1.plot(xs, lin.intercept + lin.slope * xs, ":", color=C["fit"], lw=1.2,
         label=f"Linear fit, {lin.slope:.1f} ms/node")
ax1.set_xlabel("Consortium size, $n$ access points")
ax1.set_ylabel("Propagation delay (ms)")
ax1.set_title("(a) Revocation reaches every peer", fontsize=8)
ax1.set_xticks(n)
ax1.set_ylim(0, 130)
# The n=10 95th percentile (574 ms) is driven by a single slow observation and
# is off-scale here; capping the axis keeps the median trend legible. The value
# is reported in the text and in Table V rather than hidden.
for k, xx in enumerate(n):
    if p95[k] > 130:
        ax1.annotate(f"p95 {p95[k]:.0f} ms\n(off scale)", xy=(xx, 126),
                     ha="center", va="top", fontsize=5.8, color="#8a8a8a")
ax1.grid(True, ls="-")
ax1.legend(frameon=False, loc="upper left")

# (b) the two components on a log axis, because they differ by ~100x --
# which is the finding, and a linear axis would hide it entirely
w = 1.0
ax2.bar(n - w/2, im, w, color=C["incl"], edgecolor="white", linewidth=0.8,
        label="Consensus inclusion")
ax2.bar(n + w/2, pm, w, color=C["prop"], edgecolor="white", linewidth=0.8,
        label="Propagation to all peers")
ax2.set_yscale("log")
ax2.set_ylim(5, 12000)
for k, xx in enumerate(n):
    ax2.annotate(f"{100*pm[k]/tm[k]:.1f}%", xy=(xx + w/2, pm[k]), xytext=(0, 3),
                 textcoords="offset points", ha="center", fontsize=6,
                 color="#444444")
ax2.set_xlabel("Consortium size, $n$ access points")
ax2.set_ylabel("Latency (ms, log scale)")
ax2.set_title("(b) Consensus dominates, not dissemination", fontsize=8)
ax2.set_xticks(n)
ax2.grid(True, axis="y", ls="-")
ax2.legend(frameon=False, loc="upper center", ncol=1)

fig.savefig(os.path.join(HERE, "fig_consortium.png")); plt.close(fig)

json.dump({
    "sizes": [int(x) for x in n],
    "propagation_median_ms": list(map(float, pm)),
    "propagation_p95_ms": list(map(float, p95)),
    "inclusion_median_ms": list(map(float, im)),
    "total_median_ms": list(map(float, tm)),
    "observations": samples,
    "propagation_linear_fit": {"intercept_ms": float(lin.intercept),
                               "slope_ms_per_node": float(lin.slope),
                               "r2": float(lin.rvalue ** 2)},
    "inclusion_vs_n": {"slope_ms_per_node": float(li.slope), "p": float(li.pvalue)},
    "worst_total_s": float(worst),
}, open(os.path.join(HERE, "consortium_analysis.json"), "w"), indent=2)
print("\nwrote consortium_analysis.json and fig_consortium.png")
