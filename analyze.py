#!/usr/bin/env python3
import collections
import csv
import glob
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

EXIT_MS = 20.0
GOOD_HOLD = 3.0

COLOR = {"adaptive": "#2a78d6", "pfifo": "#eb6834", "fq_codel": "#1baf7a", "cake": "#eda100",
         "cake_shaped": "#e87ba4", "fq_codel_tuned": "#008300", "adaptive_tuned": None,
         "adaptive_e25": None, "adaptive_e100": None,
         "observer": "#2a78d6", "no_observer": "#eb6834"}
ORDER = ["pfifo", "fq_codel", "fq_codel_tuned", "cake", "cake_shaped", "adaptive", "adaptive_tuned",
         "adaptive_e25", "adaptive_e100", "observer", "no_observer"]
LABEL = {"pfifo": "static pfifo", "fq_codel": "static fq_codel", "fq_codel_tuned": "static fq_codel, tuned 2/30 ms",
         "cake": "static cake", "cake_shaped": "static cake, shaped 5.4M", "adaptive": "adaptive",
         "adaptive_tuned": "adaptive + CoDel tuning", "adaptive_e25": "adaptive, enter 25 ms",
         "adaptive_e100": "adaptive, enter 100 ms", "observer": "observer attached",
         "no_observer": "observer detached"}
INK, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
MAIN_WINDOW = {"bulk": "loaded", "multi": "loaded", "udpflood": "flood", "capacity": "slow",
               "onoff": "active", "confounders": "sustained", "overhead": "loaded"}


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return np.nan


def load_run(d):
    ev = json.load(open(os.path.join(d, "events.json")))
    rows = list(csv.DictReader(open(os.path.join(d, "ctl.csv"))))
    ctl = {k: np.array([num(r[k]) for r in rows]) for k in
           ("t", "rate_mbit", "cap_mbit", "sojourn_min_ms", "sojourn_avg_ms", "drops", "inflation_ms")}
    ctl["policy"] = [r["policy"] for r in rows]
    ctl["events"] = [(float(r["t"]), r["event"]) for r in rows if r["event"]]
    pings = {}
    for f in glob.glob(os.path.join(d, "ctl.ping.*.csv")):
        name = f.rsplit(".", 2)[-2]
        pr = list(csv.DictReader(open(f)))
        pings[name] = (np.array([float(r["t"]) for r in pr]), np.array([float(r["rtt_ms"]) for r in pr]))
    flows = []
    for i, spec in enumerate(ev["flows"]):
        path = os.path.join(d, f"flow_{i}.json")
        try:
            j = json.load(open(path))
        except (OSError, ValueError):
            flows.append(None)
            continue
        actual = next((a["t"] for a in ev["actions"] if a["kind"] == "flow" and a["arg"] == spec
                       and a["t"] >= spec["start"] - 0.5), spec["start"])
        server = (j.get("server_output_json") or {}).get("intervals")
        src = server if server else j.get("intervals", [])
        iv = [(actual + x["sum"]["start"], actual + x["sum"]["end"], x["sum"]["bits_per_second"] / 1e6)
              for x in src]
        end = j.get("end", {})
        flows.append({"spec": spec, "intervals": iv,
                      "goodput": (end.get("sum_received") or end.get("sum") or {}).get("bits_per_second", np.nan) / 1e6,
                      "retrans": (end.get("sum_sent") or {}).get("retransmits", 0),
                      "lost_pct": (end.get("sum") or {}).get("lost_percent", np.nan)})
    try:
        meta = json.load(open(os.path.join(d, "ctl.meta.json")))
    except (OSError, ValueError):
        meta = {}
    return {"ev": ev, "ctl": ctl, "pings": pings, "flows": flows, "meta": meta}


def load_all(root):
    runs = collections.defaultdict(lambda: collections.defaultdict(list))
    for ev in sorted(glob.glob(os.path.join(root, "*", "*", "rep*", "events.json"))):
        d = os.path.dirname(ev)
        if not os.path.exists(os.path.join(d, "ctl.meta.json")):
            print(f"skip {d}: incomplete run (controller did not finish)", file=sys.stderr)
            continue
        try:
            r = load_run(d)
            if not r["pings"] or any(len(t) == 0 for t, _ in r["pings"].values()):
                raise ValueError("no ping samples")
        except Exception as e:
            print(f"skip {d}: {e}", file=sys.stderr)
            continue
        runs[r["ev"]["scenario"]][r["ev"]["system"]].append(r)
    return runs


def baseline(run, probe):
    t, rtt = run["pings"][probe]
    first = min([f["start"] for f in run["ev"]["flows"]] + [a[0] for a in run["ev"].get("actions_planned", [])]
                + [run["ev"]["onset"]])
    sel = rtt[t < first] if (t < first).sum() >= 3 else rtt
    return float(min(np.median(sel[i:i + 3]) for i in range(max(1, len(sel) - 2))))


def window_rtt(run, probe, win):
    t, rtt = run["pings"][probe]
    lo, hi = run["ev"]["windows"][win]
    return rtt[(t >= lo) & (t <= hi)]


def tcp_goodput(run, win):
    lo, hi = run["ev"]["windows"][win]
    total = 0.0
    for f in run["flows"]:
        if not f or f["spec"]["proto"] != "tcp":
            continue
        total += sum(mb * max(0.0, min(e, hi) - max(s, lo)) for s, e, mb in f["intervals"])
    return total / (hi - lo)


def jain(xs):
    xs = np.array([x for x in xs if np.isfinite(x)])
    return float(xs.sum() ** 2 / (len(xs) * (xs ** 2).sum())) if len(xs) and (xs ** 2).sum() > 0 else np.nan


def time_to_good(run, probe, base):
    t, rtt = run["pings"][probe]
    onset = run["ev"]["onset"]
    lo, hi = run["ev"]["windows"][MAIN_WINDOW[run["ev"]["scenario"]]]
    bad = (rtt > base + EXIT_MS)
    sel = (t >= onset) & (t <= hi)
    ts, bs = t[sel], bad[sel]
    for i in range(len(ts)):
        j = np.searchsorted(ts, ts[i] + GOOD_HOLD)
        if j >= len(ts):
            break
        if not bs[i:j + 1].any():
            return float(ts[i] - onset)
    return np.nan


def detections(run):
    return [t for t, e in run["ctl"]["events"] if "-> DEGRADED" in e]


def run_metrics(run):
    ev, scn = run["ev"], run["ev"]["scenario"]
    m = {}
    probes = sorted(run["pings"])
    base = {p: baseline(run, p) for p in probes}
    for p in probes:
        m[f"base_{p}"] = base[p]
    for win in ev["windows"]:
        for p in probes:
            r = window_rtt(run, p, win)
            if len(r):
                for q in (50, 95, 99):
                    m[f"{win}_{p}_p{q}"] = float(np.percentile(r, q))
                m[f"{win}_{p}_loss"] = np.nan
        m[f"{win}_goodput"] = tcp_goodput(run, win)
    m["drops"] = float(run["ctl"]["drops"][-1]) if len(run["ctl"]["drops"]) else np.nan
    m["retrans"] = float(sum(f["retrans"] for f in run["flows"] if f and f["spec"]["proto"] == "tcp"))
    m["swaps"] = run["meta"].get("qdisc_swaps", np.nan)
    m["retunes"] = run["meta"].get("qdisc_retunes", np.nan)
    m["changes"] = m["swaps"] + m["retunes"]
    det = detections(run)
    onset = ev["onset"]
    m["false_detections"] = float(sum(1 for t in det if t < onset))
    after = [t - onset for t in det if t >= onset]
    m["detect_s"] = after[0] if after else np.nan
    m["time_to_good_s"] = time_to_good(run, "h1", base["h1"]) if "h1" in base else np.nan
    tcp = [f["goodput"] for f in run["flows"] if f and f["spec"]["proto"] == "tcp"]
    m["jain"] = jain(tcp) if len(tcp) > 1 else np.nan
    if scn == "multi":
        by_host = collections.defaultdict(float)
        for f in run["flows"]:
            if f:
                by_host[f["spec"]["src"]] += f["goodput"]
        m["h1_share"] = by_host["h1"] / max(1e-9, sum(by_host.values()))
    udp = [f for f in run["flows"] if f and f["spec"]["proto"] == "udp"]
    if udp:
        m["udp_lost_pct"] = udp[0]["lost_pct"]
    meta = run["meta"]
    if meta:
        progs = meta.get("bpf_progs", {})
        cnt = sum(p["run_cnt"] for p in progs.values())
        ns = sum(p["run_time_ns"] for p in progs.values())
        el = meta.get("elapsed_s", np.nan)
        m["bpf_ns_per_event"] = ns / cnt if cnt else np.nan
        m["bpf_events_per_s"] = cnt / el if cnt else np.nan
        m["bpf_cpu_pct"] = 100 * ns / 1e9 / el if cnt else np.nan
        m["ctl_cpu_pct"] = 100 * meta.get("controller_cpu_s", np.nan) / el
        m["sys_busy_pct"] = 100 * meta.get("system_busy_frac", np.nan)
    return m


def agg(values):
    v = np.array([x for x in values if x is not None and np.isfinite(x)], dtype=float)
    return (float(v.mean()), float(v.std(ddof=1)) if len(v) > 1 else 0.0, len(v)) if len(v) else (np.nan, np.nan, 0)


def fmt(values, nd=1, unit=""):
    mean, sd, n = agg(values)
    if n == 0:
        return "–"
    return f"{mean:.{nd}f} ± {sd:.{nd}f}{unit}" if n > 1 else f"{mean:.{nd}f}{unit}"


def count_never(values):
    return sum(1 for x in values if x is None or not np.isfinite(x))


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def systems_of(runs, scn):
    return [s for s in ORDER if s in runs[scn]]


def report(runs, M, root):
    L = ["# Full evaluation results", "",
         "Generated by `analyze.py` from the runs in this folder. Every cell is **mean ± standard deviation "
         "across repetitions**; `n` is the number of repetitions. RTT is the h1 ping probe (5 pings/s), "
         "an interactive user sharing the bottleneck with the load. Testbed: 10 Mbit/s managed bottleneck, "
         "20 ms base RTT (80 ms for h3), downstream modem 100 Mbit/s unless the scenario changes it.", ""]

    def std_table(scn, win, extra=()):
        rows = []
        for s in systems_of(runs, scn):
            ms = M[scn][s]
            never = count_never([m["time_to_good_s"] for m in ms])
            ttg = fmt([m["time_to_good_s"] for m in ms], 1, " s")
            if never:
                ttg += f" (never in {never}/{len(ms)})"
            rows.append([LABEL[s], len(ms),
                         fmt([m.get(f"{win}_h1_p50") for m in ms]), fmt([m.get(f"{win}_h1_p95") for m in ms]),
                         fmt([m.get(f"{win}_h1_p99") for m in ms]),
                         fmt([m.get(f"{win}_goodput") for m in ms], 2),
                         fmt([m["drops"] for m in ms], 0), ttg,
                         fmt([m["changes"] for m in ms], 1)] + [f(ms) for _, f in extra])
        return table(["system", "n", "RTT p50 ms", "RTT p95 ms", "RTT p99 ms", "TCP goodput Mbit/s",
                      "drops at our qdisc", "time to good", "qdisc changes"] + [h for h, _ in extra], rows)

    for scn in ["bulk", "multi", "udpflood", "capacity", "onoff", "confounders", "overhead"]:
        if scn not in runs:
            continue
        any_run = next(iter(runs[scn].values()))[0]
        L += [f"## {scn}", "", any_run["ev"]["about"], ""]
        if scn == "bulk":
            L += [f"Window: {any_run['ev']['windows']['loaded']} s (the bulk flow's lifetime, including the "
                  "seconds before any controller reacts).", "", std_table(scn, "loaded", [
                      ("detection s", lambda ms: fmt([m["detect_s"] for m in ms], 1))]), "",
                  f"![CDF](fig_cdf_bulk.png)", ""]
        elif scn == "multi":
            L += [std_table(scn, "loaded", [
                ("h3 probe RTT p99", lambda ms: fmt([m.get("loaded_h3_p99") for m in ms])),
                ("Jain index (4 flows)", lambda ms: fmt([m["jain"] for m in ms], 3)),
                ("h1 share of goodput", lambda ms: fmt([m.get("h1_share") for m in ms], 2))]), "",
                  "Two flows each from h1 (20 ms RTT) and h3 (80 ms RTT); a fair split gives Jain 1.0 and h1 share 0.50.",
                  "", "![CDF](fig_cdf_multi.png)", ""]
        elif scn == "udpflood":
            rows = []
            for s in systems_of(runs, scn):
                ms = M[scn][s]
                rows.append([LABEL[s], len(ms), fmt([m.get("tcp_only_h1_p99") for m in ms]),
                             fmt([m.get("flood_h1_p50") for m in ms]), fmt([m.get("flood_h1_p99") for m in ms]),
                             fmt([m.get("tcp_only_goodput") for m in ms], 2), fmt([m.get("flood_goodput") for m in ms], 2),
                             fmt([m.get("udp_lost_pct") for m in ms], 0, " %"), fmt([m["changes"] for m in ms], 1)])
            L += [table(["system", "n", "RTT p99 before flood", "RTT p50 in flood", "RTT p99 in flood",
                         "TCP Mbit/s before", "TCP Mbit/s in flood", "UDP loss", "qdisc changes"], rows), "",
                  "![CDF](fig_cdf_udpflood.png)", ""]
        elif scn == "capacity":
            rows = []
            for s in systems_of(runs, scn):
                ms = M[scn][s]
                never = count_never([m["time_to_good_s"] for m in ms])
                ttg = fmt([m["time_to_good_s"] for m in ms], 1, " s") + (f" (never in {never}/{len(ms)})" if never else "")
                rows.append([LABEL[s], len(ms)] +
                            [fmt([m.get(f"{w}_h1_p99") for m in ms]) for w in ("fast_before", "slow", "fast_after")] +
                            [fmt([m.get(f"{w}_goodput") for m in ms], 2) for w in ("fast_before", "slow", "fast_after")] +
                            [ttg, fmt([m["changes"] for m in ms], 1)])
            L += ["Phases: modem at 100 Mbit/s (5–15 s), at 6 Mbit/s (15–35 s), back at 100 Mbit/s (35–70 s).", "",
                  table(["system", "n", "p99 fast, before", "p99 slow", "p99 fast, after",
                         "Mbit/s fast, before", "Mbit/s slow", "Mbit/s fast, after", "time to good (slow)",
                         "qdisc changes"], rows), "",
                  "![time series](fig_capacity_timeseries.png)", "", "![CDF](fig_cdf_capacity.png)", ""]
        elif scn == "onoff":
            L += [std_table(scn, "active"), "", "Load switches on and off every 4 s; the controller's idle "
                  "cooldown is 8 s, so a stable controller should change the qdisc once and then hold.", ""]
        elif scn == "confounders":
            rows = []
            for s in systems_of(runs, scn):
                ms = M[scn][s]
                rows.append([LABEL[s], len(ms), fmt([m["false_detections"] for m in ms], 1),
                             f"{sum(1 for m in ms if np.isfinite(m['detect_s']))}/{len(ms)}",
                             fmt([m["detect_s"] for m in ms], 1, " s"), fmt([m.get("sustained_h1_p99") for m in ms])])
            L += [table(["system", "n", "detections before the real load (false positives)",
                         "runs that detected the real load", "detection latency", "RTT p99 during real load"], rows), ""]
        elif scn == "overhead":
            rows = []
            for s in systems_of(runs, scn):
                ms = M[scn][s]
                rows.append([LABEL[s], len(ms), fmt([m.get("loaded_goodput") for m in ms], 0),
                             fmt([m.get("bpf_ns_per_event") for m in ms], 0),
                             fmt([m.get("bpf_events_per_s") for m in ms], 0),
                             fmt([m.get("bpf_cpu_pct") for m in ms], 2, " %"),
                             fmt([m.get("ctl_cpu_pct") for m in ms], 1, " %"),
                             fmt([m.get("sys_busy_pct") for m in ms], 1, " %")])
            L += [table(["system", "n", "TCP goodput Mbit/s", "eBPF ns per event", "eBPF events/s",
                         "eBPF CPU (% of one core)", "controller CPU (% of one core)", "VM busy (all cores)"], rows), "",
                  "eBPF cost comes from the kernel's own per-program counters (kernel.bpf_stats_enabled), "
                  "covering both tracepoint programs; events/s counts every packet on every interface, since "
                  "the interface filter runs inside the program.", ""]
    open(os.path.join(root, "report.md"), "w").write("\n".join(L) + "\n")
    return "\n".join(L)


def style():
    plt.rcParams.update({"font.size": 9, "axes.edgecolor": GRID, "axes.labelcolor": MUTED,
                         "xtick.color": MUTED, "ytick.color": MUTED, "axes.titlecolor": INK,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE})


def fig_cdf(runs, scn, root, title):
    win = MAIN_WINDOW[scn]
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    for s in [s for s in systems_of(runs, scn) if COLOR.get(s)]:
        rtt = np.concatenate([window_rtt(r, "h1", win) for r in runs[scn][s]])
        if not len(rtt):
            continue
        x = np.sort(rtt)
        y = np.arange(1, len(x) + 1) / len(x)
        ax.plot(x, y, color=COLOR[s], lw=2, label=f"{LABEL[s]} (n={len(runs[scn][s])})")
    ax.set_xscale("log")
    ax.set_xlabel("ping RTT, h1 to h2 (ms, log scale)")
    ax.set_ylabel("fraction of pings")
    ax.grid(True, color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, loc="lower right", fontsize=8)
    ax.set_title(title, loc="left", fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(root, f"fig_cdf_{scn}.png"), dpi=150)
    plt.close(fig)


def fig_capacity(runs, root):
    scn = "capacity"
    systems = [s for s in ["pfifo", "fq_codel", "cake", "cake_shaped", "adaptive"] if s in runs[scn]]
    fig, axes = plt.subplots(3, 1, figsize=(8, 7.2), sharex=True, gridspec_kw={"height_ratios": [2, 1.2, 1]})
    for s in systems:
        r = runs[scn][s][0]
        t, rtt = r["pings"]["h1"]
        axes[0].plot(t, rtt, color=COLOR[s], lw=1.4, label=LABEL[s])
        iv = [(a, b, mb) for f in r["flows"] if f for a, b, mb in f["intervals"]]
        if iv:
            axes[1].plot([(a + b) / 2 for a, b, _ in iv], [mb for _, _, mb in iv], color=COLOR[s], lw=1.4)
    if "adaptive" in runs[scn]:
        c = runs[scn]["adaptive"][0]["ctl"]
        axes[2].step(c["t"], c["cap_mbit"], where="post", color=COLOR["adaptive"], lw=2,
                     label="adaptive: our shaper rate")
    modem_t = [0, 15, 15, 35, 35, 75]
    modem_v = [100, 100, 6, 6, 100, 100]
    axes[2].plot(modem_t, np.minimum(modem_v, 12), color=MUTED, lw=1.2, ls=(0, (4, 3)),
                 label="modem rate (100 drawn at the top)")
    axes[0].set_yscale("log")
    axes[0].set_ylabel("ping RTT (ms, log)")
    axes[1].set_ylabel("TCP goodput (Mbit/s)")
    axes[2].set_ylabel("rate (Mbit/s)")
    axes[2].set_ylim(0, 12.5)
    axes[2].set_xlabel("time (s)")
    for ax in axes:
        ax.axvspan(15, 35, color=GRID, alpha=0.5, lw=0)
        ax.grid(True, color=GRID, lw=0.6)
        ax.set_axisbelow(True)
    axes[0].legend(frameon=False, ncol=3, fontsize=8, loc="upper left")
    axes[2].legend(frameon=False, fontsize=8, loc="lower right")
    axes[0].set_title("Downstream capacity drop (shaded: modem at 6 Mbit/s), rep 1",
                      loc="left", fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(root, "fig_capacity_timeseries.png"), dpi=150)
    plt.close(fig)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join("results", "full")
    runs = load_all(root)
    if not runs:
        sys.exit(f"no runs under {root}/")
    M = {scn: {s: [run_metrics(r) for r in rs] for s, rs in by.items()} for scn, by in runs.items()}
    style()
    titles = {"bulk": "Interactive RTT while one bulk upload runs",
              "multi": "Interactive RTT with four competing bulk flows",
              "udpflood": "Interactive RTT during an unresponsive UDP flood",
              "capacity": "Interactive RTT while the downstream modem is at 6 Mbit/s"}
    for scn, title in titles.items():
        if scn in runs:
            fig_cdf(runs, scn, root, title)
    if "capacity" in runs:
        fig_capacity(runs, root)
    with open(os.path.join(root, "metrics.csv"), "w", newline="") as f:
        keys = sorted({k for by in M.values() for ms in by.values() for m in ms for k in m})
        w = csv.writer(f)
        w.writerow(["scenario", "system", "rep"] + keys)
        for scn, by in M.items():
            for s, ms in by.items():
                for r, m in zip(runs[scn][s], ms):
                    w.writerow([scn, s, r["ev"]["rep"]] + [m.get(k, "") for k in keys])
    print(report(runs, M, root))
    print(f"\nwrote {root}/report.md, {root}/metrics.csv, {root}/fig_*.png")


if __name__ == "__main__":
    main()
