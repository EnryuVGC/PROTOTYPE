# eBPF bufferbloat detection + adaptive AQM

A closed loop, **measure → detect → decide → adapt → verify**, evaluated against static
baselines on a five-namespace testbed. An eBPF observer measures how long every packet
waits in our qdisc. A controller tells "the queue is in our qdisc" apart from "the queue is
downstream, out of our reach", and responds to each differently. The response is either to
escalate `pfifo → fq_codel → cake`, or to put a `cake` shaper below the downstream rate and
search for that rate.

```
bb-h1 10.0.1.2 ─┐                                         netem 20 ms on h2-eth0
                ├─ bb-r ── r-eth1 ══ bb-m ── m-eth1 ══ bb-h2 10.0.4.2 (server)
bb-h3 10.0.3.2 ─┘    ▲ ours: htb 10 Mbit    ▲ "modem": htb 100 Mbit + deep pfifo
(+60 ms netem)       │ + managed leaf qdisc │ (not ours; scenarios drop it to 6 Mbit)
                     └ eBPF observer + controller
```

Base RTT is 20 ms from h1 and 80 ms from h3. Normally our 10 Mbit link is the bottleneck.
When the modem drops below 10 Mbit, the queue moves into the modem, where no qdisc we
control can reach it.

## Run it

Linux only (qdiscs, namespaces and eBPF are kernel features). On this Mac the Linux side is
a Lima VM named `bloat` (Debian 12, kernel 6.1) with this folder mounted at the same path.

```sh
limactl start bloat                                                       # if stopped
limactl shell --workdir "$PWD" bloat sudo python3 experiment.py           # full evaluation, 93 runs, ~85 min
limactl shell --workdir "$PWD" bloat sudo python3 experiment.py --quick   # 1 rep of everything, ~30 min
limactl shell --workdir "$PWD" bloat sudo python3 experiment.py --only capacity --reps 10
.venv/bin/python analyze.py results/full        # on the Mac: report.md, metrics.csv, figures
```

`experiment.py --resume` skips runs that already finished. The quick two-run demo still works:
`sudo ./run_demo.sh`, then `python3 plot.py results`.

On a fresh Linux machine, run `./setup.sh` once. To drive the testbed by hand (two terminals
inside `limactl shell bloat`):

```sh
sudo ./testbed.sh up
sudo python3 controller.py                          # terminal 1: live table, Ctrl-C to stop
sudo ip netns exec bb-h2 iperf3 -s -D               # terminal 2
sudo ip netns exec bb-h1 iperf3 -c 10.0.4.2 -t 60
sudo ./testbed.sh path-rate 6mbit                   # move the bottleneck downstream
sudo ./testbed.sh path-rate 100mbit
sudo ./testbed.sh down
```

## Files

| File | Role |
|---|---|
| `testbed.sh` | Namespaces and links. Our shaped bottleneck with a 1000-packet pfifo leaf; a modem with its own shaper and deep FIFO. `path-rate` and `path-delay` change the path mid-run |
| `observer.bpf.c` | eBPF on the `net_dev_queue` and `net_dev_start_xmit` tracepoints. True per-packet sojourn time in our qdisc, whatever the qdisc is, kept as min/mean/max per 100 ms window. Per-flow bytes, packets and sojourn in an LRU map |
| `controller.py` | Every 0.5 s: read the maps, `tc` statistics and ping probes, then detect, diagnose local or remote, and act through `tc`. Logs a per-tick CSV, the pings, per-flow stats and a meta file with eBPF and controller CPU cost. `--observe-only` runs the same measurement with a fixed qdisc, which is how every static baseline is measured |
| `experiment.py` | Every scenario × system × repetition, with the order of systems shuffled in each repetition. Scripted traffic (iperf3) and path changes at fixed times |
| `analyze.py` | Percentiles, goodput (receiver side), drops, detection latency, time-to-good, Jain index, overhead. Writes `report.md`, `metrics.csv` and the figures |
| `run_demo.sh`, `plot.py` | The original two-run demo |

## How it decides

Measurements per tick:

- **delay**: minimum sojourn in our qdisc over the window. If every packet waited, it is a
  standing queue; a burst does not count.
- **inflation**: ping RTT minus the baseline. The baseline is the minimum of 3-sample rolling
  medians over 120 s, so a single lucky sample cannot drag it down.
- **rate**: egress throughput compared with our capacity.

Diagnosis, which must persist for 2 s:

| | condition | response |
|---|---|---|
| **local** | link saturated (≥ 85 %), delay > 50 ms, RTT inflated > 50 ms | next rung: `pfifo → fq_codel → cake` |
| **remote** | RTT inflated > 50 ms, our queue < 20 ms, link loaded (≥ 20 %) | `cake` shaped to 0.9 × measured rate, then autorate |
| idle-link inflation | RTT up for > 5 s with no load (route or path change) | re-baseline, no action |

```
NORMAL ──bad for 2 s──▶ DEGRADED ──act──▶ MITIGATING ──6 s dwell──▶ RECOVERED
   ▲                                       │ not better: escalate       │
   │                                       │ worse: roll back           │
   └──────────── link idle 8 s: back to the base qdisc ◀────────────────┘
```

**Autorate for the remote case.** Every 8 s the shaper is raised ×1.15, and each success
squares the step, up to ×2. If delay comes back within 8 s of a probe, the probe is blamed:
the controller falls back to the last good rate and doubles the probe interval, up to 32 s.
When a probe reaches our own link capacity, the shaper is removed.

The controller reverts only when the load is gone, never because delay is low. Low delay is
the effect of the fix, so reverting on it would flap. `--tune-codel` derives fq_codel's
`interval` from the baseline RTT (1.2 × RTT, clamped 10–200 ms) and sets `target` to 5 % of it.

## Results (`results/full/`, 3 repetitions, mean ± sd)

The full tables are in [results/full/report.md](results/full/report.md). RTT is an h1 ping
(5/s) that shares the bottleneck with the load, measured over the whole load window,
including the seconds before any controller reacts.

**Steady local bottleneck: static fq_codel and cake win.** This is the expected answer: an
always-on fq-AQM has no detection delay.

| | bulk p99 | bulk goodput | multi p99 | multi Jain | UDP flood p99 | on/off p99 |
|---|---|---|---|---|---|---|
| static pfifo | 1261 ± 37 ms | 10.12 | 1240 ± 7 ms | 0.958 | 1117 ± 16 ms | 260 ± 3 ms |
| static fq_codel | 23.8 ± 2.6 ms | 9.51 | 22.7 ± 0.5 ms | 0.994 | 22.2 ± 0.2 ms | 27.0 ± 2.4 ms |
| static cake | 22.9 ± 0.7 ms | 9.47 | 23.0 ± 1.2 ms | 0.996 | 21.9 ± 0.2 ms | 27.2 ± 2.5 ms |
| adaptive | 203.3 ± 0.2 ms | 9.66 | 261.4 ± 6.5 ms | 0.985 | 22.0 ± 0.2 ms | 200.6 ± 5.7 ms |

- Adaptive's p50 matches the static AQMs (21 ms). Its p99 is the ~3 s before it acts:
  detection takes 3.2 ± 0.0 s, and the 2 s persistence accounts for most of it. After that
  it is fq_codel. The only thing it gains is a little goodput, because it starts on pfifo.
- **On/off:** one qdisc change per run in all 3 runs, so there was no flapping across five
  load cycles.
- **UDP flood:** every fq-based policy isolates the unresponsive flow, and the TCP flow keeps
  ~4.8 Mbit/s. Under pfifo it keeps 2.4 Mbit/s at 1 s RTT.
- **RTT fairness (multi):** h3's flows have 4× h1's RTT. The h1 share of goodput is 0.53–0.56
  under fq policies and 0.60 under pfifo.

**Downstream capacity drop: here adaptive wins on latency, and pays in throughput.** The
modem goes 100 → 6 Mbit/s at 15 s and back at 35 s.

| | p99 while slow | goodput slow | p99 after | goodput after |
|---|---|---|---|---|
| static pfifo | 2116 ± 95 ms | 6.65 | 1315 ± 30 ms | 9.44 |
| static fq_codel | 2029 ± 3 ms | 6.70 | 1175 ± 134 ms | 9.87 |
| static cake | 2013 ± 19 ms | 6.52 | 1226 ± 356 ms | 9.98 |
| static cake, shaped 5.4 Mbit | 25.2 ± 3.4 ms | 5.15 | 23.4 ± 0.1 ms | **5.15** |
| adaptive | **106.7 ± 0.6 ms** | 5.47 | **23.8 ± 0.5 ms** | 6.48 |

- Without shaping, no qdisc on our side helps, because the queue is not in it. Statics reach
  ~2 s, and the modem's FIFO keeps draining after recovery, so the "after" phase is bad too.
- A static shaper set for the bad case fixes latency, but it throws away half the link for
  the whole run, even when the link is fast.
- Adaptive detects the remote queue (time to good 5.1 s), shapes to 5.44 Mbit, and the 99th
  percentile drops ~20×. A failed probe at 6.25 Mbit causes one ~100 ms episode.
- **Weakness:** after the link recovers, adaptive takes ~30 s to climb back to full rate
  (6.48 Mbit/s average in that phase, vs ~9.9). The failed probe doubled the probe interval
  to 16 s, and nothing tells the controller the path got faster. A probe triggered by a
  falling RTT, or a faster first probe after a long quiet period, would fix this. It is not
  done here.

**Threshold sensitivity.** Enter/exit 25/10 ms, 50/20 ms (default) and 100/40 ms:

| | bulk detection | bulk p99 | capacity time to good | capacity p99 slow |
|---|---|---|---|---|
| 25 / 10 ms | 2.7 s | 186 ms | 4.3 s | 95 ms |
| 50 / 20 ms | 3.2 s | 203 ms | 5.1 s | 107 ms |
| 100 / 40 ms | 4.2 s | 257 ms | 11.2 s | 222 ms |

Lower thresholds react faster. The confounder test, which counts false positives, was only
run at the default thresholds, so the cost of 25 ms is unmeasured. The results trend
smoothly; no setting is a cliff.

**Confounders (adaptive, default thresholds).** The path RTT jumped 20 → 120 ms on an idle
link, then five 1.5 s bursts followed. There were **0 false detections in 3/3 runs**. Each run
re-baselined once (+102 ms) and took no action. The real sustained load afterwards was detected in 3/3 runs
after 4.1 ± 0.2 s.

**fq_codel tuned to the RTT (2/30 ms) did not help.** Bulk p99 was unchanged (23.9 vs
23.8 ms), goodput was 7 % lower (8.84 vs 9.51), and Jain fell from 0.994 to 0.953 in the
multi scenario. `adaptive --tune-codel` was likewise no better than plain adaptive.
fq_codel's defaults suit this path.

**Observer overhead.** This is the worst case: an unshaped path with 0 ms delay, so iperf3
is CPU-bound, measured in steady state.

| | TCP goodput | eBPF cost | eBPF CPU | controller CPU |
|---|---|---|---|---|
| observer attached | 2143 ± 21 Mbit/s | 182 ± 8 ns/event, 874 k events/s | 15.9 % of one core | 0.2 % |
| observer detached | 2528 ± 116 Mbit/s | – | – | 0.2 % |

That is a 15 % throughput cost when the CPU is the limit. The interface filter runs inside
the program, so both probes fire for every packet on every interface, not just `r-eth1`.
At 10 Mbit/s, which is a few thousand events per second across all interfaces, the cost is
well under 0.1 % of a core.
The kernel's own per-program counters (`kernel.bpf_stats_enabled`) provide the numbers.

## Limits and honesty notes

- **3 repetitions, not ≥ 10.** The standard deviations are small, because the testbed is
  deterministic, but 3 runs do not support significance claims. Use `--reps 10` for
  that (~4.5 h).
- **Emulation on a laptop VM.** veth links, netem and htb are not real Wi-Fi or DOCSIS:
  there are no MAC-layer aggregation, no cross-traffic from other users and no real modem
  firmware.
- **Thresholds are design choices, not derived.** 50/20 ms, 2 s persistence, 6 s dwell
  and 8 s cooldown were picked by reasoning about the testbed, then swept as shown above.
  They were not fitted to real traces.
- **The remote diagnosis needs active probing.** It relies on ping RTT inflation. With no
  probe target, or ICMP deprioritised, the controller can only see its own queue.
- **The ping probe understates harm under fq queues.** It is a sparse flow and gets
  priority. The eBPF per-flow sojourn (`ctl.flows.csv`) shows the bulk flows' own delay.
- **Single-direction.** Only upload is managed; ingress shaping (IFB) is not implemented.
- **Tracepoints, not tc-BPF.** BCC on `net_dev_queue` / `net_dev_start_xmit` gives true
  enqueue-to-dequeue time for any qdisc. The cost is the per-packet overhead measured above.
