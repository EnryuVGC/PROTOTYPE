# eBPF bufferbloat detection + adaptive AQM — prototype

A working slice of the full loop: **measure → detect → decide → adapt → verify**,
on a three-namespace testbed with one 10 Mbit bottleneck.

```
bb-h1 ──── bb-r ──── bb-h2          r-eth1: htb 10 Mbit + leaf qdisc (managed)
 ping,    r-eth1 ▲                  h2-eth0: netem 20 ms (baseline RTT)
 iperf3          └ eBPF observer + controller
```

## Run it

Linux only (qdiscs, namespaces and eBPF are kernel features). On this Mac the
Linux side is a Lima VM named `bloat` (Debian 12, kernel 6.1) with this folder
mounted inside it at the same path.

```sh
limactl start bloat                                   # only if it is stopped
limactl shell --workdir "$PWD" bloat sudo ./run_demo.sh           # both runs, ~2 min
limactl shell --workdir "$PWD" bloat sudo ./run_demo.sh adaptive  # adaptive only, ~1 min
python3 plot.py results                               # on the Mac: table + results/demo.png
```

On a fresh Linux machine: `./setup.sh` once, then `sudo ./run_demo.sh`.

To drive it by hand (two terminals inside `limactl shell bloat`):

```sh
sudo ./testbed.sh up
sudo python3 controller.py                    # terminal 1: live table, Ctrl-C to stop
sudo ip netns exec bb-h2 iperf3 -s -D         # terminal 2
sudo ip netns exec bb-h1 iperf3 -c 10.0.2.2 -t 30
sudo ./testbed.sh down
```

## What each file does

| File | Role |
|---|---|
| `testbed.sh` | Namespaces, veth links, the shaped bottleneck with a 1000-packet pfifo, 20 ms path delay |
| `observer.bpf.c` | eBPF: stamps each packet entering the qdisc, measures sojourn time when it leaves, aggregates per 100 ms in a map; per-flow byte counters in an LRU map |
| `controller.py` | Reads the maps, qdisc statistics and a ping probe twice a second; detector; state machine; replaces the qdisc through `tc` |
| `run_demo.sh` | Same scripted load twice: controller off (control run), then on |
| `plot.py` | Percentile table and `results/demo.png` |

## How it decides

A standing queue is declared only when all of these hold for 2 s:

1. the link is saturated (egress ≥ 85 % of capacity),
2. the minimum sojourn time in every 100 ms window is above 50 ms (every packet waited),
3. the ping probe's RTT is inflated by more than 50 ms over its own minimum.

```
NORMAL ──standing queue 2 s──▶ DEGRADED ──next rung──▶ MITIGATING ──6 s dwell──▶ RECOVERED
   ▲                                                    │ no better: escalate         │
   │                                                    │ worse: roll back            │
   └───────────── link idle 8 s: back to pfifo ◀────────┴─────────────────────────────┘
```

Ladder: `pfifo → fq_codel → cake`. Enter threshold 50 ms, exit threshold 20 ms.
The controller reverts only when the load is gone, never because delay is low
(low delay is the effect of the fix, so reverting on it would flap).

## Result of the run in `results/`

One run of each, 30 s of bulk TCP, ping probe RTT while the bulk flow is active:

| Run | p50 | p95 | p99 | Bulk goodput | qdisc changes |
|---|---|---|---|---|---|
| Static pfifo (controller off) | 953.5 ms | 1252.0 ms | 1262.0 ms | 9.32 Mbit/s | 0 |
| Adaptive controller | 21.1 ms | 202.6 ms | 259.0 ms | 9.22 Mbit/s | 2 |

The adaptive p95/p99 come from the ~3 s between the load starting and the qdisc switch.

## What this prototype is not

- **One run per condition.** These are single runs, not repeated trials.
- **No comparison against static `fq_codel` or static `cake` yet.** Beating pfifo is the known result;
  that comparison is the one that tests the controller.
- **`cake` was never reached.** `fq_codel` fixed this scenario, so the escalate and rollback paths
  have not been exercised.
- **Only switching, no parameter tuning** (`target` / `interval`).
- **The ping probe understates harm under `fq_codel`**: it is a sparse flow and gets priority.
  The bulk flow's own sojourn time (orange line in the plot) stays at ~5 ms.
- **Tracepoints, not tc-BPF.** The observer hooks `net:net_dev_queue` and `net:net_dev_start_xmit`
  through BCC, because that pair gives a true enqueue-to-dequeue time for any qdisc.
- **Thresholds are illustrative**, not tuned and not sensitivity-tested.
- **Observer overhead is not measured.**
- **No fairness, multi-flow, varying-capacity or UDP-flood scenarios.**
