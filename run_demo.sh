#!/usr/bin/env bash
# Runs the same scripted load twice on a fresh testbed:
#   1. static_pfifo  controller observes but never acts   (the control condition)
#   2. adaptive      controller detects and switches the qdisc
# then prints a comparison and writes results/demo.png.
#
# Usage: sudo ./run_demo.sh            both runs
#        sudo ./run_demo.sh adaptive   just the adaptive run (good for a live demo)
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }

IDLE="${IDLE:-8}"       # quiet seconds before the bulk flow starts
LOAD="${LOAD:-30}"      # seconds of bulk TCP
TAIL="${TAIL:-14}"      # quiet seconds after it ends
OUT=results
mkdir -p "$OUT"

run() {
    local name=$1; shift
    echo; echo "=== $name: ${IDLE}s idle, ${LOAD}s bulk TCP h1 -> h2, ${TAIL}s idle ==="
    ./testbed.sh up
    ip netns exec bb-h2 iperf3 -s -1 >/dev/null 2>&1 &
    ( sleep "$IDLE"; ip netns exec bb-h1 iperf3 -c 10.0.2.2 -t "$LOAD" -J > "$OUT/$name.iperf.json" ) &
    python3 controller.py --duration $((IDLE + LOAD + TAIL)) --log "$OUT/$name.csv" "$@"
    wait
}

case "${1:-both}" in
    both)     run static_pfifo --observe-only; run adaptive ;;
    static)   run static_pfifo --observe-only ;;
    adaptive) run adaptive ;;
    *) echo "usage: $0 [both|static|adaptive]" >&2; exit 1 ;;
esac

./testbed.sh down
if python3 -c "import matplotlib" 2>/dev/null; then
    python3 plot.py "$OUT"
else
    echo "matplotlib is not installed here; run 'python3 plot.py $OUT' on the host for the summary and plot"
fi
