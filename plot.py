#!/usr/bin/env python3
"""Summarise and plot the runs in a results directory (default: results/)."""
import csv
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

RUNS = [("static_pfifo", "Static pfifo (controller off)"), ("adaptive", "Adaptive controller")]
BLUE, ORANGE = "#2a78d6", "#eb6834"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
FLOOR_MS = 0.5      # log axis: anything faster is drawn here


def load(out, name):
    path = os.path.join(out, name + ".csv")
    if not os.path.exists(path):
        return None
    rows = list(csv.DictReader(open(path)))
    num = lambda r, k: float(r[k]) if r[k] else np.nan
    run = {k: np.array([num(r, k) for r in rows]) for k in
           ("t", "rate_mbit", "sojourn_avg_ms", "drops")}
    run["changes"] = [(run["t"][i], rows[i]["policy"]) for i in range(1, len(rows))
                      if rows[i]["policy"] != rows[i - 1]["policy"]]
    ping = list(csv.DictReader(open(os.path.join(out, name + ".ping.csv"))))
    run["ping_t"] = np.array([float(r["t"]) for r in ping])
    run["ping"] = np.array([float(r["rtt_ms"]) for r in ping])
    try:
        end = json.load(open(os.path.join(out, name + ".iperf.json")))["end"]
        run["goodput"] = end["sum_received"]["bits_per_second"] / 1e6
        run["retrans"] = end["sum_sent"].get("retransmits", 0)
    except (OSError, KeyError, ValueError):
        run["goodput"] = run["retrans"] = np.nan
    busy = run["t"][run["rate_mbit"] > 0.5 * np.nanmax(run["rate_mbit"])]
    run["load"] = (busy.min(), busy.max()) if len(busy) else (0, 0)
    return run


def summary(runs):
    lines = ["Interactive probe RTT while the bulk flow is running (ms), and what it cost",
             f"{'run':<30}{'p50':>8}{'p95':>8}{'p99':>8}{'goodput':>10}{'retrans':>9}{'drops':>7}{'switches':>10}"]
    for label, r in runs:
        lo, hi = r["load"]
        rtt = r["ping"][(r["ping_t"] >= lo) & (r["ping_t"] <= hi)]
        p = np.percentile(rtt, [50, 95, 99]) if len(rtt) else [np.nan] * 3
        lines.append(f"{label:<30}{p[0]:8.1f}{p[1]:8.1f}{p[2]:8.1f}{r['goodput']:8.2f} M{r['retrans']:9.0f}"
                     f"{r['drops'][-1]:7.0f}{len(r['changes']):10d}")
    return "\n".join(lines)


def plot(runs, path):
    plt.rcParams.update({"font.size": 9, "axes.edgecolor": GRID, "axes.labelcolor": MUTED,
                         "xtick.color": MUTED, "ytick.color": MUTED, "axes.titlecolor": INK,
                         "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(2, len(runs), figsize=(5.6 * len(runs), 5.6), sharex="col", sharey="row",
                             squeeze=False, gridspec_kw={"height_ratios": [2.2, 1]})
    for col, (label, r) in enumerate(runs):
        top, bottom = axes[0][col], axes[1][col]
        top.plot(r["ping_t"], np.maximum(r["ping"], FLOOR_MS), color=BLUE, lw=1.5, label="Ping RTT, h1 to h2")
        top.plot(r["t"], np.maximum(r["sojourn_avg_ms"], FLOOR_MS), color=ORANGE, lw=1.5,
                 label="Queue sojourn time, eBPF (mean per 0.5 s)")
        top.set_yscale("log")
        top.set_title(label, loc="left", fontweight="bold")
        bottom.plot(r["t"], r["rate_mbit"], color=BLUE, lw=1.5)
        bottom.set_ylim(bottom=0)
        bottom.set_xlabel("time (s)")
        for ax in (top, bottom):
            ax.grid(True, color=GRID, lw=0.6)
            ax.set_axisbelow(True)
            for t, _ in r["changes"]:
                ax.axvline(t, color=MUTED, lw=0.8, ls=(0, (4, 3)))
        for t, policy in r["changes"]:
            top.annotate(f"qdisc: {policy}", (t, 1), xycoords=("data", "axes fraction"), xytext=(3, -10),
                         textcoords="offset points", color=INK, fontsize=8)
    axes[0][0].set_ylabel("delay (ms, log scale)")
    axes[1][0].set_ylabel("bottleneck egress (Mbit/s)")
    fig.legend(*axes[0][0].get_legend_handles_labels(), loc="upper right", ncol=2, frameon=False)
    fig.suptitle("Latency under load at a 10 Mbit bottleneck: same traffic, controller off vs on",
                 x=0.01, ha="left", color=INK, fontsize=11)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor="#fcfcfb")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "results"
    runs = [(label, r) for name, label in RUNS if (r := load(out, name))]
    if not runs:
        sys.exit(f"no runs found in {out}/")
    text = summary(runs)
    print("\n" + text)
    open(os.path.join(out, "summary.txt"), "w").write(text + "\n")
    plot(runs, os.path.join(out, "demo.png"))
    print(f"\nplot: {out}/demo.png")


if __name__ == "__main__":
    main()
