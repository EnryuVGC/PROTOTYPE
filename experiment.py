#!/usr/bin/env python3
import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = "10.0.4.2"
NS = {"h1": "bb-h1", "h3": "bb-h3"}
PROBE_H1 = "h1:bb-h1:10.0.4.2"
PROBE_H3 = "h3:bb-h3:10.0.4.2"

SYSTEMS = {
    "pfifo":          ["--observe-only", "--base", "pfifo"],
    "fq_codel":       ["--observe-only", "--base", "fq_codel"],
    "fq_codel_tuned": ["--observe-only", "--base", "fq_codel", "--codel-target", "2", "--codel-interval", "30"],
    "cake":           ["--observe-only", "--base", "cake"],
    "cake_shaped":    ["--observe-only", "--base", "cake", "--cake-bw", "5.4"],
    "adaptive":       ["--base", "pfifo"],
    "adaptive_tuned": ["--base", "pfifo", "--tune-codel"],
    "adaptive_e25":   ["--base", "pfifo", "--enter-ms", "25", "--exit-ms", "10"],
    "adaptive_e100":  ["--base", "pfifo", "--enter-ms", "100", "--exit-ms", "40"],
    "observer":       ["--observe-only", "--base", "pfifo"],
    "no_observer":    ["--observe-only", "--base", "pfifo", "--no-ebpf"],
}
CORE = ["pfifo", "fq_codel", "cake", "adaptive"]


def tcp(src, start, dur):
    return {"proto": "tcp", "src": src, "start": start, "dur": dur}


def udp(src, start, dur, rate):
    return {"proto": "udp", "src": src, "start": start, "dur": dur, "rate": rate}


SCENARIOS = {
    "bulk": dict(
        about="One bulk TCP upload from h1 next to an interactive user (the canonical case).",
        dur=42, flows=[tcp("h1", 6, 30)], actions=[],
        windows={"loaded": (6, 36)}, onset=6,
        systems=CORE + ["fq_codel_tuned", "adaptive_tuned", "adaptive_e25", "adaptive_e100"]),
    "multi": dict(
        about="Four bulk TCP flows, two from h1 (20 ms) and two from h3 (80 ms): fairness and RTT-fairness.",
        dur=42, flows=[tcp("h1", 6, 30), tcp("h1", 6, 30), tcp("h3", 6, 30), tcp("h3", 6, 30)], actions=[],
        windows={"loaded": (6, 36)}, onset=6, probes=[PROBE_H1, PROBE_H3],
        systems=CORE + ["fq_codel_tuned"]),
    "udpflood": dict(
        about="A bulk TCP flow, then an unresponsive 12 Mbit/s UDP flood from h3 that ignores drops.",
        dur=42, flows=[tcp("h1", 4, 34), udp("h3", 14, 20, "12M")], actions=[],
        windows={"tcp_only": (4, 14), "flood": (14, 34)}, onset=14,
        systems=CORE),
    "capacity": dict(
        about="Bulk TCP while the downstream modem drops from 100 to 6 Mbit/s and recovers: "
              "the queue moves out of our qdisc.",
        dur=75, flows=[tcp("h1", 5, 65)], actions=[(15, "path-rate", "6mbit"), (35, "path-rate", "100mbit")],
        windows={"fast_before": (5, 15), "slow": (15, 35), "fast_after": (35, 70)}, onset=15,
        systems=CORE + ["cake_shaped", "adaptive_e25", "adaptive_e100"]),
    "onoff": dict(
        about="Bulk TCP switching on and off every 4 s: stability stress near the thresholds.",
        dur=46, flows=[tcp("h1", 4 + 8 * i, 4) for i in range(5)], actions=[],
        windows={"active": (4, 40)}, onset=4,
        systems=CORE),
    "confounders": dict(
        about="Things that raise RTT but are not a standing queue: a 20 -> 120 ms path change on an idle "
              "link, then 1.5 s bursts; then a real sustained upload. Only the last should trigger.",
        dur=80, flows=[tcp("h1", 22 + 6 * i, 1.5) for i in range(5)] + [tcp("h1", 55, 20)],
        actions=[(10, "path-delay", "120ms")],
        windows={"bursts": (22, 52), "sustained": (55, 75)}, onset=55,
        systems=["adaptive"]),
    "overhead": dict(
        about="Observer cost: an unshaped 10 Gbit/s path with no added delay, so iperf3 is CPU-bound; "
              "observer on vs off, steady state only (first 5 s of the flow excluded).",
        dur=22, flows=[tcp("h1", 3, 17)], actions=[],
        env={"RATE": "10gbit", "PATH_RATE": "10gbit", "DELAY": "0ms", "H3_DELAY": "0ms"},
        rate_mbit=10000, windows={"loaded": (8, 19)}, onset=3,
        systems=["observer", "no_observer"]),
}


def sh(cmd, env=None):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, env=env)


def run_one(name, scn, system, rep, out, base_port):
    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(out)
    env = dict(os.environ, **scn.get("env", {}))
    sh([os.path.join(HERE, "testbed.sh"), "up"], env)

    servers = []
    for i, fl in enumerate(scn["flows"]):
        servers.append(subprocess.Popen(["ip", "netns", "exec", "bb-h2", "iperf3", "-s", "-1",
                                         "-p", str(base_port + i)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(0.5)

    cmd = ["python3", os.path.join(HERE, "controller.py"), "--quiet",
           "--duration", str(scn["dur"]), "--log", os.path.join(out, "ctl.csv"),
           "--rate-mbit", str(scn.get("rate_mbit", 10)),
           "--probes", ",".join(scn.get("probes", [PROBE_H1]))] + SYSTEMS[system]
    ctl_log = open(os.path.join(out, "ctl.log"), "w")
    ctl = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    t0 = None
    for line in ctl.stdout:
        ctl_log.write(line)
        if line.startswith("READY t0="):
            t0 = float(line.split("=", 1)[1])
            break
    if t0 is None:
        ctl.wait()
        raise RuntimeError(f"controller did not start; see {out}/ctl.log")
    pump = threading.Thread(target=lambda: [ctl_log.write(l) for l in ctl.stdout], daemon=True)
    pump.start()

    schedule = []
    for i, fl in enumerate(scn["flows"]):
        schedule.append((fl["start"], "flow", i))
    for t, kind, arg in scn["actions"]:
        schedule.append((t, kind, arg))
    schedule.sort(key=lambda x: x[0])

    clients, done_actions = [], []
    for t, kind, arg in schedule:
        delay = t0 + t - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        if kind == "flow":
            fl, port = scn["flows"][arg], base_port + arg
            c = ["ip", "netns", "exec", NS[fl["src"]], "iperf3", "-c", SERVER, "-p", str(port),
                 "-t", str(fl["dur"]), "-J", "--get-server-output"]
            if fl["proto"] == "udp":
                c += ["-u", "-b", fl["rate"], "-l", "1200"]
            f = open(os.path.join(out, f"flow_{arg}.json"), "w")
            clients.append((subprocess.Popen(c, stdout=f, stderr=subprocess.DEVNULL), f))
        else:
            sh([os.path.join(HERE, "testbed.sh"), kind, arg], env)
        done_actions.append({"t": round(time.monotonic() - t0, 3), "planned": t, "kind": kind,
                             "arg": arg if kind != "flow" else scn["flows"][arg]})

    ctl.wait()
    pump.join(timeout=2)
    ctl_log.close()
    for p, f in clients:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
        f.close()
    for s in servers:
        s.kill()
    sh([os.path.join(HERE, "testbed.sh"), "down"])

    json.dump({"scenario": name, "system": system, "rep": rep, "about": scn["about"],
               "dur": scn["dur"], "onset": scn["onset"], "windows": scn["windows"],
               "flows": scn["flows"], "actions": done_actions, "controller_cmd": cmd,
               "env": scn.get("env", {}), "finished": time.strftime("%Y-%m-%d %H:%M:%S")},
              open(os.path.join(out, "events.json"), "w"), indent=1)
    if ctl.returncode != 0:
        raise RuntimeError(f"controller exited {ctl.returncode}; see {out}/ctl.log")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--reps", type=int, default=3)
    p.add_argument("--only", default="", help="comma-separated scenarios")
    p.add_argument("--systems", default="", help="comma-separated systems (default: each scenario's list)")
    p.add_argument("--out", default=os.path.join(HERE, "results", "full"))
    p.add_argument("--seed", type=int, default=303)
    p.add_argument("--quick", action="store_true", help="1 rep, for a smoke test")
    p.add_argument("--resume", action="store_true", help="skip runs that already have events.json")
    args = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("run with sudo")
    reps = 1 if args.quick else args.reps
    names = [n for n in (args.only.split(",") if args.only else SCENARIOS) if n]
    only_sys = set(s for s in args.systems.split(",") if s)
    rng = random.Random(args.seed)

    plan = []
    for rep in range(1, reps + 1):
        for name in names:
            systems = [s for s in SCENARIOS[name]["systems"] if not only_sys or s in only_sys]
            rng.shuffle(systems)
            plan += [(rep, name, s) for s in systems]

    total, t_start, failed = len(plan), time.time(), []
    for i, (rep, name, system) in enumerate(plan, 1):
        out = os.path.join(args.out, name, system, f"rep{rep}")
        if args.resume and os.path.exists(os.path.join(out, "events.json")):
            continue
        eta = (time.time() - t_start) / max(1, i - 1) * (total - i + 1) if i > 1 else 0
        print(f"[{i}/{total}] rep {rep} {name:<12} {system:<15} (eta {eta / 60:.0f} min)", flush=True)
        try:
            run_one(name, SCENARIOS[name], system, rep, out, 5201)
        except Exception as e:
            print(f"   !! failed: {e}", flush=True)
            failed.append((rep, name, system, str(e)))
            subprocess.run([os.path.join(HERE, "testbed.sh"), "down"], capture_output=True)
    print(f"\ndone: {total - len(failed)}/{total} runs in {(time.time() - t_start) / 60:.0f} min -> {args.out}")
    for f in failed:
        print("   failed:", *f)


if __name__ == "__main__":
    main()
