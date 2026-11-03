#!/usr/bin/env bash
set -euo pipefail

RATE="${RATE:-10mbit}"
LIMIT="${LIMIT:-1000}"
DELAY="${DELAY:-20ms}"
PATH_RATE="${PATH_RATE:-100mbit}"
PATH_LIMIT="${PATH_LIMIT:-1000}"
H3_DELAY="${H3_DELAY:-60ms}"

H1=bb-h1; H3=bb-h3; R=bb-r; M=bb-m; H2=bb-h2
ALL="$H1 $H3 $R $M $H2"

down() {
    for ns in $ALL; do ip netns del "$ns" 2>/dev/null || true; done
}

offload_off() { ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null; }

up() {
    down
    modprobe -a sch_htb sch_netem sch_fq_codel sch_cake 2>/dev/null || true

    for ns in $ALL; do ip netns add "$ns"; ip -n "$ns" link set lo up; done

    ip link add h1-eth0 netns $H1 type veth peer name r-eth0 netns $R
    ip link add h3-eth0 netns $H3 type veth peer name r-eth2 netns $R
    ip link add r-eth1  netns $R  type veth peer name m-eth0 netns $M
    ip link add m-eth1  netns $M  type veth peer name h2-eth0 netns $H2

    ip -n $H1 addr add 10.0.1.2/24 dev h1-eth0
    ip -n $R  addr add 10.0.1.1/24 dev r-eth0
    ip -n $H3 addr add 10.0.3.2/24 dev h3-eth0
    ip -n $R  addr add 10.0.3.1/24 dev r-eth2
    ip -n $R  addr add 10.0.2.1/24 dev r-eth1
    ip -n $M  addr add 10.0.2.2/24 dev m-eth0
    ip -n $M  addr add 10.0.4.1/24 dev m-eth1
    ip -n $H2 addr add 10.0.4.2/24 dev h2-eth0

    for pair in $H1:h1-eth0 $H3:h3-eth0 $R:r-eth0 $R:r-eth1 $R:r-eth2 $M:m-eth0 $M:m-eth1 $H2:h2-eth0; do
        ip -n "${pair%%:*}" link set "${pair#*:}" up
        offload_off "${pair%%:*}" "${pair#*:}"
    done

    ip -n $H1 route add default via 10.0.1.1
    ip -n $H3 route add default via 10.0.3.1
    ip -n $R  route add 10.0.4.0/24 via 10.0.2.2
    ip -n $M  route add default via 10.0.2.1
    ip -n $H2 route add default via 10.0.4.1
    ip netns exec $R sysctl -qw net.ipv4.ip_forward=1
    ip netns exec $M sysctl -qw net.ipv4.ip_forward=1

    ip netns exec $R tc qdisc add dev r-eth1 root handle 1: htb default 1
    ip netns exec $R tc class add dev r-eth1 parent 1: classid 1:1 htb rate "$RATE" ceil "$RATE"
    ip netns exec $R tc qdisc add dev r-eth1 parent 1:1 handle 10: pfifo limit "$LIMIT"

    ip netns exec $M tc qdisc add dev m-eth1 root handle 1: htb default 1
    ip netns exec $M tc class add dev m-eth1 parent 1: classid 1:1 htb rate "$PATH_RATE" ceil "$PATH_RATE"
    ip netns exec $M tc qdisc add dev m-eth1 parent 1:1 handle 10: pfifo limit "$PATH_LIMIT"

    ip netns exec $H2 tc qdisc add dev h2-eth0 root netem delay "$DELAY" limit 10000
    ip netns exec $H3 tc qdisc add dev h3-eth0 root netem delay "$H3_DELAY" limit 10000

    ip netns exec $H1 ping -c 2 -W 2 -q 10.0.4.2 >/dev/null
    ip netns exec $H3 ping -c 2 -W 2 -q 10.0.4.2 >/dev/null
    echo "testbed up: $RATE managed bottleneck on r-eth1, modem $PATH_RATE, $DELAY base delay (+$H3_DELAY for h3)"
}

path_rate() {
    ip netns exec $M tc class change dev m-eth1 parent 1: classid 1:1 htb rate "$1" ceil "$1"
}

path_delay() {
    ip netns exec $H2 tc qdisc change dev h2-eth0 root netem delay "$1" limit 10000
}

status() {
    echo "== r-eth1 (managed)"; ip netns exec $R tc -s qdisc show dev r-eth1
    echo "== m-eth1 (modem)";   ip netns exec $M tc -s qdisc show dev m-eth1
}

case "${1:-}" in
    up) up ;;
    down) down; echo "testbed down" ;;
    status) status ;;
    path-rate) path_rate "${2:?rate, e.g. 6mbit}" ;;
    path-delay) path_delay "${2:?delay, e.g. 120ms}" ;;
    *) echo "usage: $0 up|down|status|path-rate RATE|path-delay DELAY" >&2; exit 1 ;;
esac
