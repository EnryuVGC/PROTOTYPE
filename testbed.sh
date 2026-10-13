#!/usr/bin/env bash
# Three-namespace testbed with one deliberate bottleneck.
#
#   bb-h1 (10.0.1.2) ---- bb-r ---- bb-h2 (10.0.2.2)
#          h1-eth0   r-eth0  r-eth1   h2-eth0
#
#   r-eth1 : htb 10 Mbit + deep pfifo leaf   <- the queue we observe and manage
#   h2-eth0: netem 20 ms on the return path  <- baseline RTT (never on the bottleneck)
#
# Usage: sudo ./testbed.sh up|down|status
set -euo pipefail

RATE="${RATE:-10mbit}"      # bottleneck capacity
DELAY="${DELAY:-20ms}"      # emulated path delay (baseline RTT)
LIMIT="${LIMIT:-1000}"      # pfifo depth in packets (~1.2 s at 10 Mbit)

H1=bb-h1; R=bb-r; H2=bb-h2

down() {
    for ns in $H1 $R $H2; do ip netns del "$ns" 2>/dev/null || true; done
}

up() {
    down
    modprobe -a sch_htb sch_netem sch_fq_codel sch_cake 2>/dev/null || true

    for ns in $H1 $R $H2; do ip netns add "$ns"; ip -n "$ns" link set lo up; done

    ip link add h1-eth0 netns $H1 type veth peer name r-eth0 netns $R
    ip link add h2-eth0 netns $H2 type veth peer name r-eth1 netns $R

    ip -n $H1 addr add 10.0.1.2/24 dev h1-eth0
    ip -n $R  addr add 10.0.1.1/24 dev r-eth0
    ip -n $R  addr add 10.0.2.1/24 dev r-eth1
    ip -n $H2 addr add 10.0.2.2/24 dev h2-eth0

    ip -n $H1 link set h1-eth0 up; ip -n $R link set r-eth0 up
    ip -n $R  link set r-eth1 up;  ip -n $H2 link set h2-eth0 up

    ip -n $H1 route add default via 10.0.1.1
    ip -n $H2 route add default via 10.0.2.1
    ip netns exec $R sysctl -qw net.ipv4.ip_forward=1

    # Without this, 64 KB TSO super-packets cross the "link" and a 1000-packet
    # queue stops meaning 1000 x 1500 bytes.
    ip netns exec $H1 ethtool -K h1-eth0 tso off gso off gro off >/dev/null
    ip netns exec $H2 ethtool -K h2-eth0 tso off gso off gro off >/dev/null
    ip netns exec $R  ethtool -K r-eth0  tso off gso off gro off >/dev/null
    ip netns exec $R  ethtool -K r-eth1  tso off gso off gro off >/dev/null

    # Bottleneck: shaper on top, the managed queue as its leaf.
    ip netns exec $R tc qdisc add dev r-eth1 root handle 1: htb default 1
    ip netns exec $R tc class add dev r-eth1 parent 1: classid 1:1 htb rate "$RATE" ceil "$RATE"
    ip netns exec $R tc qdisc add dev r-eth1 parent 1:1 handle 10: pfifo limit "$LIMIT"

    # Path delay, on the reverse direction only (ACKs and echo replies).
    ip netns exec $H2 tc qdisc add dev h2-eth0 root netem delay "$DELAY" limit 10000

    ip netns exec $H1 ping -c 2 -W 2 -q 10.0.2.2 >/dev/null && echo "testbed up: $RATE bottleneck on r-eth1, $DELAY baseline RTT"
}

status() {
    ip netns exec $R tc -s qdisc show dev r-eth1
}

case "${1:-}" in
    up) up ;;
    down) down; echo "testbed down" ;;
    status) status ;;
    *) echo "usage: $0 up|down|status" >&2; exit 1 ;;
esac
