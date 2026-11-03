#!/usr/bin/env python3
import argparse
import collections
import csv
import json
import os
import re
import resource
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
MTU_BITS = 1514 * 8
HERE = os.path.dirname(os.path.abspath(__file__))


def sh(cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def cpu_ticks():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]]
    idle = v[3] + v[4]
    return sum(v) - idle, sum(v)


class Qdisc:

    def __init__(self, ns, dev, parent, pfifo_limit):
        self.tc = ["ip", "netns", "exec", ns, "tc"] if ns else ["tc"]
        self.dev, self.parent, self.pfifo_limit = dev, parent, pfifo_limit
        self.handle = 100
        self.kind, self.params = None, {}
        self.swaps = self.retunes = 0

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

    def _args(self, kind, params):
        if kind == "pfifo":
            return ["limit", str(self.pfifo_limit)]
        if kind == "fq_codel":
            out = []
            if params.get("target_ms"):
                out += ["target", f"{params['target_ms']:.1f}ms"]
            if params.get("interval_ms"):
                out += ["interval", f"{params['interval_ms']:.0f}ms"]
            return out
        if kind == "cake":
            bw = params.get("bandwidth_mbit")
            return ["bandwidth", f"{int(bw * 1000)}kbit"] if bw else ["unlimited"]
        raise ValueError(kind)

    def apply(self, kind, params=None):
        params = {k: v for k, v in (params or {}).items() if v}
        if kind == self.kind and params == self.params:
            return None
        if kind == self.kind and kind != "pfifo":
            sh(self.tc + ["qdisc", "change", "dev", self.dev, "parent", self.parent,
                          "handle", f"{self.handle}:", kind] + self._args(kind, params))
            self.retunes += 1
        else:
            self.handle += 1
            sh(self.tc + ["qdisc", "replace", "dev", self.dev, "parent", self.parent,
                          "handle", f"{self.handle}:", kind] + self._args(kind, params))
            if self.kind is not None:
                self.swaps += 1
        self.kind, self.params = kind, params
        return self.describe()

    def describe(self):
        p = self.params
        if self.kind == "cake":
            return f"cake {p['bandwidth_mbit']:.2f}M" if p.get("bandwidth_mbit") else "cake"
        if self.kind == "fq_codel" and p:
            return f"fq_codel {p.get('target_ms', 5):.1f}/{p.get('interval_ms', 100):.0f}ms"
        return self.kind


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
        self.prev = {}

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

    def flow_stats(self, dt):
        out, seen = [], {}
        for k, v in self.flows.items():
            key = (k.saddr, k.daddr, k.sport, k.dport, k.proto)
            seen[key] = (v.bytes, v.pkts, v.sojourn_ns)
            pb, pp, ps = self.prev.get(key, (0, 0, 0))
            db, dp, ds = v.bytes - pb, v.pkts - pp, v.sojourn_ns - ps
            if db > 0 or dp > 0:
                out.append((db * 8 / dt / 1e6, (ds / dp / 1e6) if dp else None, key))
        self.prev = seen
        ip = lambda a: socket.inet_ntoa(struct.pack("I", a))
        proto = {1: "icmp", 6: "tcp", 17: "udp"}
        named = [(f"{proto.get(k[4], k[4])} {ip(k[0])}:{k[2]}>{ip(k[1])}:{k[3]}", mbit, soj)
                 for mbit, soj, k in sorted(out, key=lambda x: -x[0])]
        return len(seen), named

    def prog_stats(self):
        stats = {}
        for name, fn in getattr(self.bpf, "funcs", {}).items():
            try:
                with open(f"/proc/self/fdinfo/{fn.fd}") as f:
                    info = dict(line.split(":", 1) for line in f if ":" in line)
                stats[name.decode() if isinstance(name, bytes) else name] = {"run_cnt": int(info.get("run_cnt", 0)),
                               "run_time_ns": int(info.get("run_time_ns", 0))}
            except (OSError, ValueError):
                pass
        return stats


class PingProbe(threading.Thread):

    def __init__(self, name, ns, target, t0, log_path, baseline_window):
        super().__init__(daemon=True)
        self.name = name
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
            if not m or "DUP!" in line:
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
            rtts = [r for _, r in self.history]
        if len(rtts) >= 3:
            base = min(sorted(rtts[i:i + 3])[1] for i in range(len(rtts) - 2))
        else:
            base = min(rtts, default=None)
        return (statistics.median(fresh) if fresh else None), base

    def rebase(self, now, keep):
        with self.lock:
            while self.history and self.history[0][0] < now - keep:
                self.history.popleft()

    def stop(self):
        self.proc.terminate()
        self.log.flush()


class Controller:
    def __init__(self, args, qdisc, emit):
        self.a, self.qdisc, self.emit = args, qdisc, emit
        self.state = "NORMAL"
        self.rung = LADDER.index(args.base)
        self.shaped = args.cake_bw
        self.diag = None
        self.base_rtt = None
        self.recent = collections.deque(maxlen=64)
        self.bad_since = self.good_since = self.idle_since = None
        self.changed_at = self.locked_until = 0.0
        self.before = None
        self.prev = (self.rung, self.shaped)
        self.told_top = False
        self.probe_every = args.probe_every
        self.next_probe_at = 0.0
        self.probe_raised_at = None
        self.last_good_bw = None
        self.step_mult = args.probe_step

    @property
    def policy(self):
        return self.qdisc.describe() or LADDER[self.rung]

    def params(self, rung, shaped):
        kind = LADDER[rung]
        if kind == "cake":
            return {"bandwidth_mbit": shaped}
        if kind == "fq_codel":
            if self.a.codel_target or self.a.codel_interval:
                return {"target_ms": self.a.codel_target, "interval_ms": self.a.codel_interval}
            if self.a.tune_codel and self.base_rtt:
                interval = min(max(1.2 * self.base_rtt, 10.0), 200.0)
                target = max(0.05 * interval, 1.5 * MTU_BITS / (self.a.rate_mbit * 1e6) * 1e3)
                return {"target_ms": round(target, 1), "interval_ms": round(interval)}
        return {}

    def install(self):
        return self.qdisc.apply(LADDER[self.rung], self.params(self.rung, self.shaped))

    def cap(self):
        return self.shaped or self.a.rate_mbit

    def _harm(self, since):
        vals = [h for t, h in self.recent if t >= since]
        return statistics.median(vals) if vals else 0.0

    def _set(self, rung, shaped, now, why):
        old = self.policy
        self.before = self._harm(now - 3)
        self.prev = (self.rung, self.shaped)
        self.rung, self.shaped = rung, shaped
        desc = self.install()
        self.changed_at, self.told_top = now, False
        self.bad_since = self.good_since = self.idle_since = None
        if desc:
            self.emit(f"qdisc {old} -> {desc}  ({why})")

    def _goto(self, state, why):
        self.emit(f"state {self.state} -> {state}  ({why})")
        self.state = state

    def _respond(self, now, rate):
        a = self.a
        if self.diag == "remote":
            if self.probe_raised_at is not None and now - self.probe_raised_at < a.probe_window:
                bw = self.last_good_bw
                self.probe_every = min(self.probe_every * 2, a.probe_max)
                self.step_mult = a.probe_step
                why = f"rate probe failed, back to {bw:.2f}M, next probe in {self.probe_every:g}s"
            else:
                bw = max(a.shape_frac * min(rate, self.cap()), a.min_mbit)
                why = f"queue is downstream: shape to {a.shape_frac:g} x {rate:.2f}M measured"
            self.probe_raised_at = None
            self.next_probe_at = now + self.probe_every
            self._set(LADDER.index("cake"), bw, now, why)
            return True
        if self.rung + 1 < len(LADDER):
            self._set(self.rung + 1, self.shaped, now, "escalate")
            return True
        return False

    def step(self, now, rate, delay, inflation, base_rtt):
        a = self.a
        self.base_rtt = base_rtt or self.base_rtt
        harm = max(delay, inflation or 0.0)
        self.recent.append((now, harm))

        cap = self.cap()
        saturated = rate >= a.saturation * cap
        loaded = rate >= a.load_frac * a.rate_mbit
        inflated = inflation is None or inflation > a.enter_ms
        local = saturated and delay > a.enter_ms and inflated
        remote = (not a.no_remote) and inflation is not None and inflation > a.enter_ms \
            and delay < a.exit_ms and loaded
        bad = local or remote
        good = delay < a.exit_ms and (inflation is None or inflation < a.exit_ms)
        idle = rate < a.load_frac * a.rate_mbit

        held = lambda since: (now - since) if since is not None else -1
        self.bad_since = (self.bad_since or now) if bad else None
        self.good_since = (self.good_since or now) if good else None
        self.idle_since = (self.idle_since or now) if idle else None
        if bad:
            self.diag = "local" if local else "remote"

        if a.observe_only:
            return

        if self.state == "NORMAL":
            if now >= self.locked_until and held(self.bad_since) >= a.persist:
                what = (f"standing queue in our qdisc: min sojourn {delay:.0f} ms on a saturated link"
                        if self.diag == "local" else
                        f"queue downstream: RTT +{inflation:.0f} ms, our queue {delay:.0f} ms at {rate:.1f}M")
                self._goto("DEGRADED", f"{what}, for {a.persist:g}s")

        elif self.state == "DEGRADED":
            if self._respond(now, rate):
                self._goto("MITIGATING", f"holding for {a.dwell:g}s dwell")
            else:
                self._goto("MITIGATING", "already on the strongest policy")
                self.changed_at = now

        elif self.state == "MITIGATING":
            if now - self.changed_at < a.dwell:
                return
            after = self._harm(self.changed_at + a.dwell / 2)
            if held(self.good_since) >= a.exit_persist:
                self._goto("RECOVERED", f"harm {self.before:.0f} -> {after:.0f} ms, keeping {self.policy}")
            elif self.before and after > 1.25 * self.before and (self.rung, self.shaped) != self.prev:
                self._set(*self.prev, now, f"rollback: harm got worse, {self.before:.0f} -> {after:.0f} ms")
                self.locked_until = now + a.cooldown
                self._goto("NORMAL", f"locked out for {a.cooldown:g}s")
            elif held(self.bad_since) >= a.persist:
                if not self._respond(now, rate) and not self.told_top:
                    self.emit("top of the ladder and still degraded; holding")
                    self.told_top = True

        elif self.state == "RECOVERED":
            if held(self.bad_since) >= a.persist:
                self._goto("DEGRADED", f"degraded again under {self.policy} ({self.diag})")
            elif held(self.idle_since) >= a.cooldown and not a.no_revert and \
                    (self.rung, self.shaped) != (LADDER.index(a.base), a.cake_bw):
                self.probe_every, self.probe_raised_at, self.step_mult = a.probe_every, None, a.probe_step
                self._set(LADDER.index(a.base), a.cake_bw, now, f"link idle for {a.cooldown:g}s, back to base")
                self._goto("NORMAL", "load gone")
            elif self.shaped and self.probe_raised_at is None and now >= self.next_probe_at \
                    and held(self.good_since) >= a.exit_persist and rate >= 0.8 * self.shaped:
                self.last_good_bw = self.shaped
                new = self.shaped * self.step_mult
                self.probe_raised_at = now
                self._set(self.rung, None if new >= a.rate_mbit else new, now,
                          f"rate probe up x{self.step_mult:.2f}")
            elif self.probe_raised_at is not None and now - self.probe_raised_at >= a.probe_window:
                self.probe_raised_at = None
                self.probe_every = a.probe_every
                self.step_mult = min(self.step_mult ** 2, 2.0)
                self.next_probe_at = now
                if self.shaped is None:
                    self.emit("rate probe reached link capacity; shaper off")


def parse_probes(spec):
    out = []
    for item in spec.split(","):
        if item.strip():
            name, ns, target = item.split(":")
            out.append((name, ns, target))
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_argument_group("where")
    g.add_argument("--ns", default="bb-r", help="namespace of the bottleneck router ('' for none)")
    g.add_argument("--dev", default="r-eth1", help="bottleneck egress interface")
    g.add_argument("--parent", default="1:1", help="shaper class holding the managed leaf qdisc")
    g.add_argument("--rate-mbit", type=float, default=10.0, help="capacity of our shaper")
    g.add_argument("--pfifo-limit", type=int, default=1000)
    g.add_argument("--probes", default="h1:bb-h1:10.0.4.2", help="name:netns:target[,...] ping probes")
    g = p.add_argument_group("policy")
    g.add_argument("--base", choices=LADDER, default="pfifo", help="policy when nothing is wrong")
    g.add_argument("--codel-target", type=float, help="static fq_codel target, ms")
    g.add_argument("--codel-interval", type=float, help="static fq_codel interval, ms")
    g.add_argument("--tune-codel", action="store_true", help="derive fq_codel target/interval from baseline RTT")
    g.add_argument("--cake-bw", type=float, help="static cake shaper, Mbit/s (default: unlimited)")
    g.add_argument("--observe-only", action="store_true", help="measure and detect, never change the qdisc")
    g.add_argument("--no-revert", action="store_true", help="keep the stronger policy after load ends")
    g.add_argument("--no-remote", action="store_true", help="disable the downstream-queue diagnosis")
    g = p.add_argument_group("thresholds")
    g.add_argument("--tick", type=float, default=0.5, help="control loop period, s")
    g.add_argument("--enter-ms", type=float, default=50, help="upper threshold: delay above this is bad")
    g.add_argument("--exit-ms", type=float, default=20, help="lower threshold: delay below this is good")
    g.add_argument("--persist", type=float, default=2, help="s a bad condition must last before acting")
    g.add_argument("--exit-persist", type=float, default=3, help="s a good condition must last")
    g.add_argument("--dwell", type=float, default=6, help="s to hold after a change before judging it")
    g.add_argument("--cooldown", type=float, default=8, help="s of idle link before reverting to base")
    g.add_argument("--saturation", type=float, default=0.85, help="fraction of capacity that counts as saturated")
    g.add_argument("--load-frac", type=float, default=0.2, help="below this fraction of capacity the link is idle")
    g.add_argument("--baseline-window", type=float, default=120, help="s over which min RTT is the baseline")
    g.add_argument("--rebase-after", type=float, default=5, help="s of idle-link inflation before re-baselining")
    g = p.add_argument_group("cake autorate (REMOTE diagnosis)")
    g.add_argument("--shape-frac", type=float, default=0.9, help="shape to this fraction of the measured rate")
    g.add_argument("--min-mbit", type=float, default=0.5)
    g.add_argument("--probe-every", type=float, default=8, help="s between upward rate probes")
    g.add_argument("--probe-max", type=float, default=32, help="max s between probes after failures")
    g.add_argument("--probe-step", type=float, default=1.15, help="multiply the shaper by this on a probe")
    g.add_argument("--probe-window", type=float, default=8, help="s after a probe in which degradation blames it")
    g = p.add_argument_group("run")
    g.add_argument("--no-ebpf", action="store_true", help="fallback: derive delay from backlog / rate")
    g.add_argument("--duration", type=float, default=0, help="stop after this many seconds (0 = until Ctrl-C)")
    g.add_argument("--log", default="results/run.csv")
    g.add_argument("--quiet", action="store_true", help="no per-tick table on stdout")
    args = p.parse_args()

    if os.geteuid() != 0:
        sys.exit("run as root (loading eBPF and changing qdiscs both need it)")
    os.makedirs(os.path.dirname(args.log) or ".", exist_ok=True)
    stem = args.log[:-4] if args.log.endswith(".csv") else args.log

    events = []
    def emit(msg):
        events.append(msg)
        print(f"  >>> {msg}", flush=True)

    qdisc = Qdisc(args.ns, args.dev, args.parent, args.pfifo_limit)
    qdisc.stats()
    ctl = Controller(args, qdisc, emit)
    ctl.install()

    observer, stats_was = None, None
    if not args.no_ebpf:
        try:
            stats_was = open("/proc/sys/kernel/bpf_stats_enabled").read().strip()
            open("/proc/sys/kernel/bpf_stats_enabled", "w").write("1")
            observer = Observer(args.dev)
        except Exception as e:
            print(f"!! eBPF observer failed to load ({e}); falling back to backlog/rate", flush=True)

    t0 = time.monotonic()
    probes = [PingProbe(name, ns, target, t0, f"{stem}.ping.{name}.csv", args.baseline_window)
              for name, ns, target in parse_probes(args.probes)]
    for pr in probes:
        pr.start()
    cpu0, ru0 = cpu_ticks(), resource.getrusage(resource.RUSAGE_SELF)
    print(f"READY t0={t0:.6f}", flush=True)

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    fields = ["t", "state", "policy", "diag", "rate_mbit", "cap_mbit", "backlog_bytes", "qdelay_derived_ms",
              "sojourn_min_ms", "sojourn_avg_ms", "sojourn_max_ms", "rtt_ms", "rtt_base_ms", "inflation_ms",
              "drops", "flows", "event"]
    mode = "observe-only" if args.observe_only else "adaptive"
    source = "eBPF sojourn (min per 100 ms window)" if observer else "backlog / rate (no eBPF)"
    if not args.quiet:
        print(f"{mode} controller on {args.dev}: {args.rate_mbit:g} Mbit, base {ctl.policy}, delay signal: {source}")
        print(f"{'t':>6} {'state':<10} {'qdisc':<16} {'rate':>6} {'backlog':>8} {'sojourn':>8} "
              f"{'rtt':>7} {'infl':>6} {'drops':>6}  top flow")

    flog = open(f"{stem}.flows.csv", "w", newline="")
    fw = csv.writer(flog)
    fw.writerow(["t", "flow", "mbit", "sojourn_ms"])
    with open(args.log, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        root, _ = qdisc.stats()
        prev_bytes, prev_t, drops, prev_leaf = root["bytes"], t0, 0, (qdisc.handle, 0)
        idle_infl_since = None
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
            derived = leaf["backlog"] * 8 / (ctl.cap() * 1e6) * 1e3

            soj = observer.sojourn() if observer else None
            nflows, fl = observer.flow_stats(dt) if observer else (0, [])
            for name, mbit, s in fl[:8]:
                fw.writerow([f"{t:.2f}", name, f"{mbit:.3f}", "" if s is None else f"{s:.2f}"])

            samples = [(pr.name,) + pr.sample(t) for pr in probes]
            infl = [(r - b) for _, r, b in samples if r is not None and b is not None]
            inflation = max(infl) if infl else None
            bases = [b for _, _, b in samples if b is not None]
            base_rtt = max(bases) if bases else None
            rtt = next((r for _, r, _ in samples if r is not None), None)
            delay = soj[0] if soj else derived

            idle_now = rate < args.load_frac * args.rate_mbit
            if idle_now and inflation is not None and inflation > args.exit_ms:
                idle_infl_since = idle_infl_since or t
                if t - idle_infl_since >= args.rebase_after:
                    for pr in probes:
                        pr.rebase(t, keep=2.0)
                    emit(f"path baseline moved (+{inflation:.0f} ms with the link idle): re-baselined")
                    idle_infl_since = None
            else:
                idle_infl_since = None

            n_events = len(events)
            ctl.step(t, rate, delay, inflation, base_rtt)
            fmt = lambda v, nd=1: "" if v is None else f"{v:.{nd}f}"
            w.writerow({
                "t": f"{t:.2f}", "state": ctl.state, "policy": ctl.policy, "diag": ctl.diag or "",
                "rate_mbit": f"{rate:.2f}", "cap_mbit": f"{ctl.cap():.2f}",
                "backlog_bytes": leaf["backlog"], "qdelay_derived_ms": f"{derived:.1f}",
                "sojourn_min_ms": fmt(soj[0] if soj else None), "sojourn_avg_ms": fmt(soj[1] if soj else None),
                "sojourn_max_ms": fmt(soj[2] if soj else None), "rtt_ms": fmt(rtt), "rtt_base_ms": fmt(base_rtt),
                "inflation_ms": fmt(inflation), "drops": drops, "flows": nflows,
                "event": " | ".join(events[n_events:]),
            })
            f.flush()
            flog.flush()
            if not args.quiet:
                ms = lambda v: "-" if v is None else f"{v:.0f}ms"
                top = f"{fl[0][0]} {fl[0][1]:.1f}M" if fl else ""
                print(f"{t:6.1f} {ctl.state:<10} {ctl.policy:<16} {rate:5.1f}M {leaf['backlog'] // 1000:6d}kB "
                      f"{ms(soj[0] if soj else derived):>8} {ms(rtt):>7} {ms(inflation):>6} {drops:6d}  {top}",
                      flush=True)

    elapsed = time.monotonic() - t0
    cpu1, ru1 = cpu_ticks(), resource.getrusage(resource.RUSAGE_SELF)
    meta = {
        "elapsed_s": elapsed,
        "observer": bool(observer),
        "bpf_progs": observer.prog_stats() if observer else {},
        "controller_cpu_s": (ru1.ru_utime - ru0.ru_utime) + (ru1.ru_stime - ru0.ru_stime),
        "system_busy_frac": (cpu1[0] - cpu0[0]) / max(1, cpu1[1] - cpu0[1]),
        "qdisc_swaps": qdisc.swaps, "qdisc_retunes": qdisc.retunes,
        "final_policy": ctl.policy, "args": vars(args),
    }
    with open(f"{stem}.meta.json", "w") as mf:
        json.dump(meta, mf, indent=1)

    for pr in probes:
        pr.stop()
    flog.close()
    if stats_was is not None:
        open("/proc/sys/kernel/bpf_stats_enabled", "w").write(stats_was)
    if not args.observe_only and qdisc.kind != args.base:
        qdisc.apply(args.base)
        print(f"  >>> exit: restored {args.base}")


if __name__ == "__main__":
    main()
