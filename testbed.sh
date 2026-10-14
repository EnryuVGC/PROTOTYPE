#!/usr/bin/env bash
set -euo pipefail

RATE="${RATE:-10mbit}"
DELAY="${DELAY:-20ms}"
LIMIT="${LIMIT:-1000}"

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

    ip netns exec $H1 ethtool -K h1-eth0 tso off gso off gro off >/dev/null
    ip netns exec $H2 ethtool -K h2-eth0 tso off gso off gro off >/dev/null
    ip netns exec $R  ethtool -K r-eth0  tso off gso off gro off >/dev/null
    ip netns exec $R  ethtool -K r-eth1  tso off gso off gro off >/dev/null

    ip netns exec $R tc qdisc add dev r-eth1 root handle 1: htb default 1
    ip netns exec $R tc class add dev r-eth1 parent 1: classid 1:1 htb rate "$RATE" ceil "$RATE"
    ip netns exec $R tc qdisc add dev r-eth1 parent 1:1 handle 10: pfifo limit "$LIMIT"

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
