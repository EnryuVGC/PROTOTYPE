#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends iproute2 ethtool iperf3 iputils-ping \
    python3-bpfcc "linux-headers-$(uname -r)"
sudo apt-get install -y -qq "linux-modules-extra-$(uname -r)" 2>/dev/null || true
sudo modprobe -a sch_htb sch_netem sch_fq_codel sch_cake
echo "ok: kernel $(uname -r), $(python3 -c 'import bcc; print("bcc", bcc.__version__)')"
