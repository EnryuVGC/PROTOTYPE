#!/usr/bin/env python3
import argparse
import collections
import csv
import json
import os
import re
import signal
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time

LADDER = ["pfifo", "fq_codel", "cake"]
WINDOW_NS = 100_000_000
NSLOTS = 64
HERE = os.path.dirname(os.path.abspath(__file__))


def sh(cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


class Qdisc:
    def __init__(self, ns, dev, parent, pfifo_limit):
        self.tc = ["ip", "netns", "exec", ns, "tc"] if ns else ["tc"]
        self.dev, self.parent, self.pfifo_limit = dev, parent, pfifo_limit
        self.handle = 100

    def stats(self):
        root = leaf = None
        for q in json.loads(sh(self.tc + ["-s", "-j", "qdisc", "show", "dev", self.dev])):
            if q.get("root"):
                root = q
            elif q.get("parent") == self.parent:
                leaf = q
        if root is None or leaf is None:
            raise RuntimeError(f"no shaper + leaf qdisc on {self.dev}; run testbed.sh up first")
        return root, leaf

    def apply(self, kind):
        self.handle += 1
        args = ["limit", str(self.pfifo_limit)] if kind == "pfifo" else []
        sh(self.tc + ["qdisc", "replace", "dev", self.dev, "parent", self.parent,
                      "handle", f"{self.handle}:", kind] + args)


class Observer:
    def __init__(self, dev):
        from bcc import BPF
        name = dev.encode()
        if len(name) > 15:
            raise ValueError("interface name too long")
        padded = name.ljust(16, b"\0")
        mask = (b"\xff" * (len(name) + 1)).ljust(16, b"\0")
        u64 = lambda b: f"0x{int.from_bytes(b, 'little'):x}ULL"
        self.bpf = BPF(src_file=os.path.join(HERE, "observer.bpf.c"), cflags=[
            "-Wno-macro-redefined",
            f"-DNAME_LO={u64(padded[:8])}", f"-DNAME_HI={u64(padded[8:])}",
            f"-DMASK_LO={u64(mask[:8])}", f"-DMASK_HI={u64(mask[8:])}",
            f"-DWINDOW_NS={WINDOW_NS}ULL", f"-DNSLOTS={NSLOTS}",
        ])
        self.slots = self.bpf["slots"]
        self.flows = self.bpf["flows"]
        self.next_epoch = time.monotonic_ns() // WINDOW_NS
        self.prev_bytes = {}

    def sojourn(self):
        now_epoch = time.monotonic_ns() // WINDOW_NS
        epochs = range(max(self.next_epoch, now_epoch - NSLOTS + 2), now_epoch)
        self.next_epoch = now_epoch
        mins, count, total, peak = [], 0, 0, 0
        for epoch in epochs:
            s = self.slots[epoch % NSLOTS]
            if s.epoch != epoch or s.count == 0:
                mins.append(0)
                continue
            mins.append(s.min_ns)
            count += s.count
            total += s.sum_ns
            peak = max(peak, s.max_ns)
        if not mins:
            return None
        return min(mins) / 1e6, (total / count / 1e6 if count else 0.0), peak / 1e6

    def top_flows(self, dt, n=3):
        rates, seen = [], {}
        for k, v in self.flows.items():
            key = (k.saddr, k.daddr, k.sport, k.dport, k.proto)
            seen[key] = v.bytes
            delta = v.bytes - self.prev_bytes.get(key, 0)
            if delta > 0:
                rates.append((delta * 8 / dt / 1e6, key))
        self.prev_bytes = seen
        ip = lambda a: socket.inet_ntoa(struct.pack("I", a))
        proto = {1: "icmp", 6: "tcp", 17: "udp"}
        return len(seen), [
            f"{proto.get(k[4], k[4])} {ip(k[0])}:{k[2]}>{ip(k[1])}:{k[3]} {mbit:.1f}Mbit"
            for mbit, k in sorted(rates, reverse=True)[:n]]


class PingProbe(threading.Thread):
    def __init__(self, ns, target, t0, log_path, baseline_window):
        super().__init__(daemon=True)
        cmd = ["ping", "-n", "-i", "0.2", target]
        self.proc = subprocess.Popen((["ip", "netns", "exec", ns] if ns else []) + cmd,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.t0, self.lock, self.fresh = t0, threading.Lock(), []
        self.history = collections.deque()
        self.baseline_window = baseline_window
        self.log = open(log_path, "w", newline="")
        self.writer = csv.writer(self.log)
        self.writer.writerow(["t", "rtt_ms"])

    def run(self):
        for line in self.proc.stdout:
            m = re.search(r"time=([\d.]+) ms", line)
            if not m:
                continue
            t, rtt = time.monotonic() - self.t0, float(m.group(1))
            self.writer.writerow([f"{t:.3f}", rtt])
            with self.lock:
                self.fresh.append(rtt)
                self.history.append((t, rtt))

    def sample(self, now):
        with self.lock:
            fresh, self.fresh = self.fresh, []
            while self.history and self.history[0][0] < now - self.baseline_window:
                self.history.popleft()
            base = min((r for _, r in self.history), default=None)
        return (statistics.median(fresh) if fresh else None), base

    def stop(self):
        self.proc.terminate()
        self.log.flush()


class Controller:
    def __init__(self, args, qdisc, emit):
        self.a, self.qdisc, self.emit = args, qdisc, emit
        self.state = "NORMAL"
        self.rung = LADDER.index(args.base)
        self.policy = args.base
        self.recent = collections.deque(maxlen=64)
        self.bad_since = self.good_since = self.idle_since = None
        self.changed_at = self.locked_until = 0.0
        self.before = None
        self.prev_rung = self.rung
        self.told_top = False

    def _median_delay(self, since):
        vals = [d for t, d in self.recent if t >= since]
        return statistics.median(vals) if vals else 0.0

    def _switch(self, rung, now, why):
        old = self.policy
        self.before = self._median_delay(now - 3)
        self.prev_rung, self.rung, self.policy = self.rung, rung, LADDER[rung]
        self.qdisc.apply(self.policy)
        self.changed_at, self.told_top = now, False
        self.bad_since = self.good_since = self.idle_since = None
        self.emit(f"qdisc {old} -> {self.policy}  ({why})")

    def _goto(self, state, why):
        self.emit(f"state {self.state} -> {state}  ({why})")
        self.state = state

    def step(self, now, rate_mbit, delay_ms, inflation_ms):
        a = self.a
        self.recent.append((now, delay_ms))
        saturated = rate_mbit >= a.saturation * a.rate_mbit
        bad = saturated and delay_ms > a.enter_ms and (inflation_ms is None or inflation_ms > a.enter_ms)
        good = delay_ms < a.exit_ms and (inflation_ms is None or inflation_ms < a.exit_ms)
        idle = rate_mbit < 0.5 * a.rate_mbit

        held = lambda since: since is not None and now - since
        self.bad_since = (self.bad_since or now) if bad else None
        self.good_since = (self.good_since or now) if good else None
        self.idle_since = (self.idle_since or now) if idle else None

        if a.observe_only:
            return

        if self.state == "NORMAL":
            if now >= self.locked_until and held(self.bad_since) >= a.persist:
                self._goto("DEGRADED", f"standing queue for {a.persist:g}s: delay {delay_ms:.0f} ms on a saturated link")

        elif self.state == "DEGRADED":
            if self.rung + 1 < len(LADDER):
                self._switch(self.rung + 1, now, "escalate")
                self._goto("MITIGATING", f"holding for {a.dwell:g}s dwell")
            else:
                self._goto("MITIGATING", "already on the strongest policy")
                self.changed_at = now

        elif self.state == "MITIGATING":
            if now - self.changed_at < a.dwell:
                return
            after = self._median_delay(self.changed_at + a.dwell / 2)
            if held(self.good_since) >= a.exit_persist:
                self._goto("RECOVERED", f"delay {self.before:.0f} -> {after:.0f} ms, keeping {self.policy}")
            elif self.before and after > 1.25 * self.before and self.rung != self.prev_rung:
                self._switch(self.prev_rung, now, f"rollback: delay got worse, {self.before:.0f} -> {after:.0f} ms")
                self.locked_until = now + a.cooldown
                self._goto("NORMAL", f"locked out for {a.cooldown:g}s")
            elif held(self.bad_since) >= a.persist:
                if self.rung + 1 < len(LADDER):
                    self._switch(self.rung + 1, now, f"{LADDER[self.rung]} did not help, escalate")
                elif not self.told_top:
                    self.emit("top of the ladder and still degraded; holding")
                    self.told_top = True

        elif self.state == "RECOVERED":
            if held(self.bad_since) >= a.persist:
                self._goto("DEGRADED", f"degraded again under {self.policy}")
            elif held(self.idle_since) >= a.cooldown and not a.no_revert and self.policy != a.base:
                self._switch(LADDER.index(a.base), now, f"link idle for {a.cooldown:g}s, back to base")
                self._goto("NORMAL", "load gone")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ns", default="bb-r", help="namespace of the bottleneck router ('' for none)")
    p.add_argument("--dev", default="r-eth1", help="bottleneck egress interface")
    p.add_argument("--parent", default="1:1", help="shaper class holding the managed leaf qdisc")
    p.add_argument("--rate-mbit", type=float, default=10.0, help="bottleneck capacity")
    p.add_argument("--pfifo-limit", type=int, default=1000)
    p.add_argument("--base", choices=LADDER, default="pfifo", help="policy when nothing is wrong")
    p.add_argument("--probe-ns", default="bb-h1")
    p.add_argument("--probe-target", default="10.0.2.2")
    p.add_argument("--tick", type=float, default=0.5, help="control loop period, s")
    p.add_argument("--enter-ms", type=float, default=50, help="upper threshold: delay above this is bad")
    p.add_argument("--exit-ms", type=float, default=20, help="lower threshold: delay below this is good")
    p.add_argument("--persist", type=float, default=2, help="s a bad condition must last before acting")
    p.add_argument("--exit-persist", type=float, default=3, help="s a good condition must last")
    p.add_argument("--dwell", type=float, default=6, help="s to hold after a change before judging it")
    p.add_argument("--cooldown", type=float, default=8, help="s of idle link before reverting to base")
    p.add_argument("--saturation", type=float, default=0.85, help="fraction of capacity that counts as saturated")
    p.add_argument("--baseline-window", type=float, default=120, help="s over which min RTT is the baseline")
    p.add_argument("--observe-only", action="store_true", help="measure and detect, never change the qdisc")
    p.add_argument("--no-revert", action="store_true", help="keep the stronger policy after load ends")
    p.add_argument("--no-ebpf", action="store_true", help="fallback: derive delay from backlog / rate")
    p.add_argument("--no-probe", action="store_true", help="do not run the ping probe")
    p.add_argument("--duration", type=float, default=0, help="stop after this many seconds (0 = until Ctrl-C)")
    p.add_argument("--log", default="results/run.csv")
    args = p.parse_args()

    if os.geteuid() != 0:
        sys.exit("run as root (loading eBPF and changing qdiscs both need it)")
    os.makedirs(os.path.dirname(args.log) or ".", exist_ok=True)

    qdisc = Qdisc(args.ns, args.dev, args.parent, args.pfifo_limit)
    qdisc.stats()
    qdisc.apply(args.base)

    observer = None
    if not args.no_ebpf:
        try:
            observer = Observer(args.dev)
        except Exception as e:
            print(f"!! eBPF observer failed to load ({e}); falling back to backlog/rate", flush=True)

    t0 = time.monotonic()
    probe = None
    if not args.no_probe:
        probe = PingProbe(args.probe_ns, args.probe_target, t0, args.log.replace(".csv", "") + ".ping.csv",
                          args.baseline_window)
        probe.start()

    events = []
    def emit(msg):
        events.append(msg)
        print(f"  >>> {msg}", flush=True)

    ctl = Controller(args, qdisc, emit)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    fields = ["t", "state", "policy", "rate_mbit", "backlog_bytes", "qdelay_derived_ms", "sojourn_min_ms",
              "sojourn_avg_ms", "sojourn_max_ms", "rtt_ms", "rtt_base_ms", "inflation_ms", "drops", "flows", "event"]
    mode = "observe-only" if args.observe_only else "adaptive"
    source = "eBPF sojourn (min per 100 ms window)" if observer else "backlog / rate (no eBPF)"
    print(f"{mode} controller on {args.dev}: {args.rate_mbit:g} Mbit, base {args.base}, delay signal: {source}")
    print(f"{'t':>6} {'state':<10} {'qdisc':<8} {'rate':>6} {'backlog':>8} {'derived':>8} {'sojourn':>8} "
          f"{'rtt':>7} {'infl':>6} {'drops':>6}  top flow")

    with open(args.log, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        root, _ = qdisc.stats()
        prev_bytes, prev_t, drops, prev_leaf = root["bytes"], t0, 0, (qdisc.handle, 0)
        while not stop.wait(args.tick):
            now = time.monotonic()
            t, dt = now - t0, now - prev_t
            if args.duration and t > args.duration:
                break
            root, leaf = qdisc.stats()
            rate = (root["bytes"] - prev_bytes) * 8 / dt / 1e6
            prev_bytes, prev_t = root["bytes"], now
            if prev_leaf[0] == qdisc.handle:
                drops += max(0, leaf["drops"] - prev_leaf[1])
            else:
                drops += leaf["drops"]
            prev_leaf = (qdisc.handle, leaf["drops"])
            derived = leaf["backlog"] * 8 / (args.rate_mbit * 1e6) * 1e3

            soj = observer.sojourn() if observer else None
            nflows, top = observer.top_flows(dt) if observer else (0, [])
            rtt, base = probe.sample(t) if probe else (None, None)
            inflation = rtt - base if rtt is not None and base is not None else None
            delay = soj[0] if soj else derived

            n_events = len(events)
            ctl.step(t, rate, delay, inflation)
            fmt = lambda v, nd=1: "" if v is None else f"{v:.{nd}f}"
            w.writerow({
                "t": f"{t:.2f}", "state": ctl.state, "policy": ctl.policy, "rate_mbit": f"{rate:.2f}",
                "backlog_bytes": leaf["backlog"], "qdelay_derived_ms": f"{derived:.1f}",
                "sojourn_min_ms": fmt(soj[0] if soj else None), "sojourn_avg_ms": fmt(soj[1] if soj else None),
                "sojourn_max_ms": fmt(soj[2] if soj else None), "rtt_ms": fmt(rtt), "rtt_base_ms": fmt(base),
                "inflation_ms": fmt(inflation), "drops": drops, "flows": nflows,
                "event": " | ".join(events[n_events:]),
            })
            f.flush()
            ms = lambda v: "-" if v is None else f"{v:.0f}ms"
            print(f"{t:6.1f} {ctl.state:<10} {ctl.policy:<8} {rate:5.1f}M {leaf['backlog'] // 1000:6d}kB "
                  f"{ms(derived):>8} {ms(soj[0] if soj else None):>8} {ms(rtt):>7} {ms(inflation):>6} {drops:6d}  "
                  f"{top[0] if top else ''}", flush=True)

    if probe:
        probe.stop()
    if ctl.policy != args.base:
        qdisc.apply(args.base)
        print(f"  >>> exit: restored {args.base}")


if __name__ == "__main__":
    main()
